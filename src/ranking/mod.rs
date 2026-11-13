use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use rand::{
    distr::{weighted::WeightedIndex, Distribution},
    RngExt,
};

use crate::poller::RunStats;

const FAILED_COOLDOWN: Duration = Duration::from_secs(60 * 60 * 24);
const FAILED_WEIGHT: f64 = 0.001;
const RERUN_COOLDOWN: Duration = Duration::from_secs(60 * 60 * 24);
const RERUN_WEIGHT: f64 = 0.001;
const DNS_SAMPLE_SIZE: usize = 10;
const DEFAULT_PORT: u16 = 8333;
const SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(60 * 15);
const MAX_ADDRESSES: usize = 3_500_000;
const EVICT_TO: usize = 3_000_000;
const MAX_FAILED_ATTEMPTS: u8 = 7;

type WeightedIp = (IpAddr, f64);

#[derive(Debug)]
pub enum PeerStatus {
    SuccessfulRun(RunStats),
    ShouldMeasure(SystemTime),
    Gossiped(SystemTime),
    NoFilters,
    Rejected,
    Failed((SystemTime, u8)),
}

#[derive(Debug, Default, Clone)]
pub struct AddressSet {
    addrs: Arc<Mutex<HashMap<SocketAddr, PeerStatus>>>,
}

impl AddressSet {
    pub fn with_max_capacity() -> Self {
        Self {
            addrs: Arc::new(Mutex::new(HashMap::with_capacity(MAX_ADDRESSES))),
        }
    }

    pub fn add_gossiped(&self, addrs: Vec<SocketAddr>) {
        self.add_gossiped_bounded(addrs, MAX_ADDRESSES, EVICT_TO);
    }

    fn add_gossiped_bounded(&self, addrs: Vec<SocketAddr>, max: usize, evict_to: usize) {
        let mut lock = self.addrs.lock().unwrap();
        for addr in addrs {
            if lock.len() >= max && !lock.contains_key(&addr) {
                let evicted = evict(&mut lock, evict_to);
                tracing::info!("Evicted {evicted} addresses, {} remain", lock.len());
                if lock.len() >= max {
                    tracing::warn!("Address set is full, dropping gossiped addresses");
                    return;
                }
            }
            lock.entry(addr)
                .or_insert(PeerStatus::Gossiped(SystemTime::now()));
        }
    }

    pub fn prune(&self) -> usize {
        let mut lock = self.addrs.lock().unwrap();
        let before = lock.len();
        lock.retain(|_, status| {
            !matches!(status, PeerStatus::Failed((_, attempts)) if *attempts >= MAX_FAILED_ATTEMPTS)
        });
        before - lock.len()
    }

    pub fn successful_run(&self, addr: SocketAddr, stats: RunStats) {
        let mut lock = self.addrs.lock().unwrap();
        lock.insert(addr, PeerStatus::SuccessfulRun(stats));
    }

    pub fn failed_run(&self, addr: SocketAddr) {
        self.mark_failed(addr);
    }

    pub fn successful_handshake(&self, addr: SocketAddr) {
        let mut lock = self.addrs.lock().unwrap();
        lock.insert(addr, PeerStatus::ShouldMeasure(SystemTime::now()));
    }

    pub fn unsupported(&self, addr: SocketAddr) {
        let mut lock = self.addrs.lock().unwrap();
        lock.insert(addr, PeerStatus::NoFilters);
    }

    pub fn rejected(&self, addr: SocketAddr) {
        let mut lock = self.addrs.lock().unwrap();
        lock.insert(addr, PeerStatus::Rejected);
    }

    pub fn failed_handshake(&self, addr: SocketAddr) {
        self.mark_failed(addr);
    }

    fn mark_failed(&self, addr: SocketAddr) {
        let mut lock = self.addrs.lock().unwrap();
        let attempts = match lock.get(&addr) {
            Some(PeerStatus::Failed((_, attempts))) => attempts.saturating_add(1),
            _ => 1,
        };
        lock.insert(addr, PeerStatus::Failed((SystemTime::now(), attempts)));
    }

    pub fn sample_for_handshake(&self) -> Option<SocketAddr> {
        self.sample_by_weight(|status, now| match status {
            PeerStatus::Gossiped(then) => Some(age_secs(now, *then)),
            PeerStatus::Failed((then, _))
                if now.duration_since(*then).unwrap_or_default() > FAILED_COOLDOWN =>
            {
                Some(FAILED_WEIGHT)
            }
            _ => None,
        })
    }

    pub fn sample_for_run(&self) -> Option<SocketAddr> {
        self.sample_by_weight(|status, now| match status {
            PeerStatus::ShouldMeasure(then) => Some(age_secs(now, *then)),
            PeerStatus::SuccessfulRun(stats)
                if now.duration_since(stats.when).unwrap_or_default() > RERUN_COOLDOWN =>
            {
                Some(RERUN_WEIGHT)
            }
            _ => None,
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        let lock = self.addrs.lock().unwrap();
        let (v4, v6): (Vec<WeightedIp>, Vec<WeightedIp>) = lock
            .iter()
            .filter_map(|(addr, status)| match status {
                PeerStatus::SuccessfulRun(stats) if addr.port() == DEFAULT_PORT => {
                    let weight = 1.0 / stats.time_elapsed.as_secs_f64().max(f64::EPSILON);
                    Some((addr.ip(), weight))
                }
                _ => None,
            })
            .partition(|(ip, _)| ip.is_ipv4());
        Snapshot {
            v4,
            v6,
            taken: Instant::now(),
        }
    }

    fn sample_by_weight(
        &self,
        weight: impl Fn(&PeerStatus, SystemTime) -> Option<f64>,
    ) -> Option<SocketAddr> {
        let lock = self.addrs.lock().unwrap();
        let now = SystemTime::now();
        let (addrs, weights): (Vec<SocketAddr>, Vec<f64>) = lock
            .iter()
            .filter_map(|(addr, status)| weight(status, now).map(|w| (*addr, w)))
            .unzip();
        let dist = WeightedIndex::new(weights).ok()?;
        let idx = dist.sample(&mut rand::rng());
        Some(addrs[idx])
    }
}

#[derive(Debug)]
pub struct Snapshot {
    v4: Vec<WeightedIp>,
    v6: Vec<WeightedIp>,
    taken: Instant,
}

impl Snapshot {
    pub fn is_stale(&self) -> bool {
        self.taken.elapsed() > SNAPSHOT_MAX_AGE
    }

    pub fn sample(&self) -> Vec<IpAddr> {
        let mut rng = rand::rng();
        let mut v4 = weighted_shuffle(&self.v4, &mut rng);
        v4.extend(weighted_shuffle(&self.v6, &mut rng));
        v4
    }
}

fn weighted_shuffle(peers: &[WeightedIp], rng: &mut impl rand::Rng) -> Vec<IpAddr> {
    let mut keyed: Vec<(f64, IpAddr)> = peers
        .iter()
        .map(|(ip, weight)| (rng.random::<f64>().powf(1.0 / weight), *ip))
        .collect();
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    keyed
        .into_iter()
        .take(DNS_SAMPLE_SIZE)
        .map(|(_, ip)| ip)
        .collect()
}

fn evict(addrs: &mut HashMap<SocketAddr, PeerStatus>, target: usize) -> usize {
    let excess = addrs.len().saturating_sub(target);
    if excess == 0 {
        return 0;
    }
    let mut rng = rand::rng();
    let mut candidates: Vec<((u8, u8, u64), SocketAddr)> = addrs
        .iter()
        .filter_map(|(addr, status)| {
            let rank = match status {
                PeerStatus::Failed((then, attempts)) => {
                    let secs = then
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    (0, u8::MAX - attempts, secs)
                }
                PeerStatus::Rejected | PeerStatus::NoFilters => (1, 0, 0),
                PeerStatus::Gossiped(_) => (2, 0, rng.random::<u64>()),
                PeerStatus::ShouldMeasure(_) | PeerStatus::SuccessfulRun(_) => return None,
            };
            Some((rank, *addr))
        })
        .collect();
    if candidates.len() > excess {
        candidates.select_nth_unstable_by_key(excess, |(rank, _)| *rank);
        candidates.truncate(excess);
    }
    for (_, addr) in &candidates {
        addrs.remove(addr);
    }
    candidates.len()
}

fn age_secs(now: SystemTime, then: SystemTime) -> f64 {
    now.duration_since(then).unwrap_or_default().as_secs() as f64 + 1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_at(when: SystemTime) -> RunStats {
        RunStats {
            time_elapsed: Duration::from_secs(1),
            when,
        }
    }

    #[test]
    fn sample_for_run_skips_recent_runs() {
        let set = AddressSet::default();
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        set.successful_run(addr, run_at(SystemTime::now()));
        assert_eq!(set.sample_for_run(), None);
        let stale = SystemTime::now() - RERUN_COOLDOWN - Duration::from_secs(1);
        set.successful_run(addr, run_at(stale));
        assert_eq!(set.sample_for_run(), Some(addr));
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn status(set: &AddressSet, addr: SocketAddr) -> String {
        format!("{:?}", set.addrs.lock().unwrap().get(&addr))
    }

    fn attempts(set: &AddressSet, addr: SocketAddr) -> u8 {
        match set.addrs.lock().unwrap().get(&addr) {
            Some(PeerStatus::Failed((_, attempts))) => *attempts,
            other => panic!("expected failed status, got {other:?}"),
        }
    }

    #[test]
    fn empty_set_samples_nothing() {
        let set = AddressSet::default();
        assert_eq!(set.sample_for_handshake(), None);
        assert_eq!(set.sample_for_run(), None);
        assert!(set.snapshot().sample().is_empty());
    }

    #[test]
    fn gossip_does_not_overwrite_known_status() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.successful_handshake(peer);
        set.add_gossiped(vec![peer]);
        assert!(status(&set, peer).starts_with("Some(ShouldMeasure"));
        assert_eq!(set.sample_for_handshake(), None);
        assert_eq!(set.sample_for_run(), Some(peer));
    }

    #[test]
    fn gossiped_addresses_are_handshake_candidates() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.add_gossiped(vec![peer]);
        assert_eq!(set.sample_for_handshake(), Some(peer));
        assert_eq!(set.sample_for_run(), None);
        assert!(set.snapshot().sample().is_empty());
    }

    #[test]
    fn handshake_outcomes_remove_address_from_handshake_pool() {
        let set = AddressSet::default();
        let good = addr("1.2.3.4:8333");
        let unsupported = addr("5.6.7.8:8333");
        let failed = addr("9.9.9.9:8333");
        set.add_gossiped(vec![good, unsupported, failed]);
        set.successful_handshake(good);
        set.unsupported(unsupported);
        set.failed_handshake(failed);
        assert_eq!(set.sample_for_handshake(), None);
        assert_eq!(set.sample_for_run(), Some(good));
    }

    #[test]
    fn rejected_addresses_are_never_sampled() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.add_gossiped(vec![peer]);
        set.rejected(peer);
        set.add_gossiped(vec![peer]);
        assert!(status(&set, peer).starts_with("Some(Rejected"));
        assert_eq!(set.sample_for_handshake(), None);
        assert_eq!(set.sample_for_run(), None);
        assert!(set.snapshot().sample().is_empty());
    }

    #[test]
    fn failed_addresses_are_retried_after_cooldown() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.failed_handshake(peer);
        assert_eq!(set.sample_for_handshake(), None);
        let stale = SystemTime::now() - FAILED_COOLDOWN - Duration::from_secs(1);
        set.addrs
            .lock()
            .unwrap()
            .insert(peer, PeerStatus::Failed((stale, 1)));
        assert_eq!(set.sample_for_handshake(), Some(peer));
    }

    #[test]
    fn failures_count_attempts() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.failed_handshake(peer);
        assert_eq!(attempts(&set, peer), 1);
        set.failed_run(peer);
        assert_eq!(attempts(&set, peer), 2);
        set.successful_handshake(peer);
        set.failed_handshake(peer);
        assert_eq!(attempts(&set, peer), 1);
    }

    #[test]
    fn failure_attempts_saturate() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.addrs
            .lock()
            .unwrap()
            .insert(peer, PeerStatus::Failed((SystemTime::now(), u8::MAX)));
        set.failed_handshake(peer);
        assert_eq!(attempts(&set, peer), u8::MAX);
    }

    #[test]
    fn failed_run_removes_address_from_dns_sample() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.successful_run(peer, run_at(SystemTime::now()));
        assert_eq!(set.snapshot().sample(), vec![peer.ip()]);
        set.failed_run(peer);
        assert!(set.snapshot().sample().is_empty());
    }

    #[test]
    fn dns_sample_only_contains_successful_runs() {
        let set = AddressSet::default();
        let good = addr("1.2.3.4:8333");
        set.add_gossiped(vec![addr("2.2.2.2:8333")]);
        set.successful_handshake(addr("3.3.3.3:8333"));
        set.unsupported(addr("4.4.4.4:8333"));
        set.failed_handshake(addr("5.5.5.5:8333"));
        set.successful_run(good, run_at(SystemTime::now()));
        assert_eq!(set.snapshot().sample(), vec![good.ip()]);
    }

    #[test]
    fn dns_sample_is_capped() {
        let set = AddressSet::default();
        for i in 0..(DNS_SAMPLE_SIZE as u8 * 2) {
            set.successful_run(addr(&format!("1.2.3.{i}:8333")), run_at(SystemTime::now()));
        }
        let sample = set.snapshot().sample();
        assert_eq!(sample.len(), DNS_SAMPLE_SIZE);
        let mut unique = sample.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), DNS_SAMPLE_SIZE);
    }

    #[test]
    fn dns_sample_is_capped_per_address_family() {
        let set = AddressSet::default();
        for i in 0..(DNS_SAMPLE_SIZE as u8 * 2) {
            set.successful_run(addr(&format!("1.2.3.{i}:8333")), run_at(SystemTime::now()));
        }
        set.successful_run(addr("[2001:db8::1]:8333"), run_at(SystemTime::now()));
        set.successful_run(addr("[2001:db8::2]:8333"), run_at(SystemTime::now()));
        for _ in 0..20 {
            let sample = set.snapshot().sample();
            assert_eq!(
                sample.iter().filter(|ip| ip.is_ipv4()).count(),
                DNS_SAMPLE_SIZE
            );
            assert_eq!(sample.iter().filter(|ip| ip.is_ipv6()).count(), 2);
        }
    }

    #[test]
    fn dns_sample_handles_zero_elapsed_time() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        let stats = RunStats {
            time_elapsed: Duration::ZERO,
            when: SystemTime::now(),
        };
        set.successful_run(peer, stats);
        assert_eq!(set.snapshot().sample(), vec![peer.ip()]);
    }

    #[test]
    fn dns_sample_only_contains_default_port_peers() {
        let set = AddressSet::default();
        let default = addr("1.2.3.4:8333");
        set.successful_run(default, run_at(SystemTime::now()));
        set.successful_run(addr("5.6.7.8:18333"), run_at(SystemTime::now()));
        set.successful_run(addr("1.2.3.4:9999"), run_at(SystemTime::now()));
        for _ in 0..20 {
            assert_eq!(set.snapshot().sample(), vec![default.ip()]);
        }
    }

    #[test]
    fn dns_sample_prefers_faster_peers() {
        let set = AddressSet::default();
        let fast = addr("1.1.1.1:8333");
        let slow = addr("2.2.2.2:8333");
        let stats = |secs| RunStats {
            time_elapsed: Duration::from_secs(secs),
            when: SystemTime::now(),
        };
        set.successful_run(fast, stats(1));
        set.successful_run(slow, stats(100));
        let fast_first = (0..1_000)
            .filter(|_| set.snapshot().sample()[0] == fast.ip())
            .count();
        assert!(
            fast_first > 900,
            "fast peer ranked first {fast_first} times"
        );
    }

    #[test]
    fn gossip_evicts_when_full() {
        let set = AddressSet::default();
        let failed = addr("1.1.1.1:8333");
        let rejected = addr("2.2.2.2:8333");
        let measuring = addr("3.3.3.3:8333");
        let good = addr("4.4.4.4:8333");
        set.failed_handshake(failed);
        set.rejected(rejected);
        set.successful_handshake(measuring);
        set.successful_run(good, run_at(SystemTime::now()));
        let new = addr("5.5.5.5:8333");
        set.add_gossiped_bounded(vec![new], 4, 3);
        let lock = set.addrs.lock().unwrap();
        assert_eq!(lock.len(), 4);
        assert!(!lock.contains_key(&failed));
        assert!(lock.contains_key(&rejected));
        assert!(lock.contains_key(&new));
    }

    #[test]
    fn eviction_prefers_most_failed_then_oldest() {
        let set = AddressSet::default();
        let now = SystemTime::now();
        let old = now - Duration::from_secs(100);
        let many = addr("1.1.1.1:8333");
        let few_old = addr("2.2.2.2:8333");
        let few_new = addr("3.3.3.3:8333");
        {
            let mut lock = set.addrs.lock().unwrap();
            lock.insert(many, PeerStatus::Failed((now, 5)));
            lock.insert(few_old, PeerStatus::Failed((old, 1)));
            lock.insert(few_new, PeerStatus::Failed((now, 1)));
        }
        let mut lock = set.addrs.lock().unwrap();
        assert_eq!(evict(&mut lock, 2), 1);
        assert!(!lock.contains_key(&many));
        assert_eq!(evict(&mut lock, 1), 1);
        assert!(!lock.contains_key(&few_old));
        assert!(lock.contains_key(&few_new));
    }

    #[test]
    fn eviction_falls_back_to_gossiped() {
        let set = AddressSet::default();
        let gossiped: Vec<SocketAddr> = (0..10).map(|i| addr(&format!("1.2.3.{i}:8333"))).collect();
        set.add_gossiped(gossiped);
        set.unsupported(addr("1.2.3.0:8333"));
        let mut lock = set.addrs.lock().unwrap();
        assert_eq!(evict(&mut lock, 5), 5);
        assert_eq!(lock.len(), 5);
        assert!(!lock.contains_key(&addr("1.2.3.0:8333")));
    }

    #[test]
    fn full_set_of_protected_addresses_drops_gossip() {
        let set = AddressSet::default();
        set.successful_handshake(addr("1.1.1.1:8333"));
        set.successful_run(addr("2.2.2.2:8333"), run_at(SystemTime::now()));
        set.add_gossiped_bounded(vec![addr("3.3.3.3:8333")], 2, 1);
        assert_eq!(set.addrs.lock().unwrap().len(), 2);
    }

    #[test]
    fn known_addresses_are_not_blocked_when_full() {
        let set = AddressSet::default();
        let peer = addr("1.1.1.1:8333");
        set.successful_handshake(peer);
        set.add_gossiped_bounded(vec![peer], 1, 0);
        assert!(status(&set, peer).starts_with("Some(ShouldMeasure"));
    }

    #[test]
    fn prune_removes_repeatedly_failed_addresses() {
        let set = AddressSet::default();
        let dead = addr("1.1.1.1:8333");
        let flaky = addr("2.2.2.2:8333");
        let gossiped = addr("3.3.3.3:8333");
        {
            let mut lock = set.addrs.lock().unwrap();
            lock.insert(
                dead,
                PeerStatus::Failed((SystemTime::now(), MAX_FAILED_ATTEMPTS)),
            );
            lock.insert(flaky, PeerStatus::Failed((SystemTime::now(), 1)));
        }
        set.add_gossiped(vec![gossiped]);
        assert_eq!(set.prune(), 1);
        let lock = set.addrs.lock().unwrap();
        assert!(!lock.contains_key(&dead));
        assert!(lock.contains_key(&flaky));
        assert!(lock.contains_key(&gossiped));
    }

    #[test]
    fn snapshot_is_isolated_from_later_updates() {
        let set = AddressSet::default();
        let peer = addr("1.2.3.4:8333");
        set.successful_run(peer, run_at(SystemTime::now()));
        let snapshot = set.snapshot();
        set.failed_run(peer);
        set.successful_run(addr("5.6.7.8:8333"), run_at(SystemTime::now()));
        assert_eq!(snapshot.sample(), vec![peer.ip()]);
        assert!(!snapshot.is_stale());
    }
}
