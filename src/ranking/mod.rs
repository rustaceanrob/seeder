use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
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

#[derive(Debug)]
pub enum PeerStatus {
    SuccessfulRun(RunStats),
    ShouldMeasure(SystemTime),
    Gossiped(SystemTime),
    NoFilters,
    Failed((SystemTime, u8)),
}

#[derive(Debug, Default, Clone)]
pub struct AddressSet {
    addrs: Arc<Mutex<HashMap<SocketAddr, PeerStatus>>>,
}

impl AddressSet {
    pub fn add_gossiped(&self, addrs: Vec<SocketAddr>) {
        let mut lock = self.addrs.lock().unwrap();
        for addr in addrs {
            lock.entry(addr)
                .or_insert(PeerStatus::Gossiped(SystemTime::now()));
        }
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

    pub fn sample_successful(&self) -> Vec<IpAddr> {
        let lock = self.addrs.lock().unwrap();
        let mut rng = rand::rng();
        let mut keyed: Vec<(f64, SocketAddr)> = lock
            .iter()
            .filter_map(|(addr, status)| match status {
                PeerStatus::SuccessfulRun(stats) if addr.port() == DEFAULT_PORT => {
                    let weight = 1.0 / stats.time_elapsed.as_secs_f64().max(f64::EPSILON);
                    let key = rng.random::<f64>().powf(1.0 / weight);
                    Some((key, *addr))
                }
                _ => None,
            })
            .collect();
        keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        keyed.truncate(DNS_SAMPLE_SIZE);
        keyed.into_iter().map(|(_, addr)| addr.ip()).collect()
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
        assert!(set.sample_successful().is_empty());
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
        assert!(set.sample_successful().is_empty());
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
        assert_eq!(set.sample_successful(), vec![peer.ip()]);
        set.failed_run(peer);
        assert!(set.sample_successful().is_empty());
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
        assert_eq!(set.sample_successful(), vec![good.ip()]);
    }

    #[test]
    fn dns_sample_is_capped() {
        let set = AddressSet::default();
        for i in 0..(DNS_SAMPLE_SIZE as u8 * 2) {
            set.successful_run(addr(&format!("1.2.3.{i}:8333")), run_at(SystemTime::now()));
        }
        let sample = set.sample_successful();
        assert_eq!(sample.len(), DNS_SAMPLE_SIZE);
        let mut unique = sample.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), DNS_SAMPLE_SIZE);
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
        assert_eq!(set.sample_successful(), vec![peer.ip()]);
    }

    #[test]
    fn dns_sample_only_contains_default_port_peers() {
        let set = AddressSet::default();
        let default = addr("1.2.3.4:8333");
        set.successful_run(default, run_at(SystemTime::now()));
        set.successful_run(addr("5.6.7.8:18333"), run_at(SystemTime::now()));
        set.successful_run(addr("1.2.3.4:9999"), run_at(SystemTime::now()));
        for _ in 0..20 {
            assert_eq!(set.sample_successful(), vec![default.ip()]);
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
            .filter(|_| set.sample_successful()[0] == fast.ip())
            .count();
        assert!(
            fast_first > 900,
            "fast peer ranked first {fast_first} times"
        );
    }
}
