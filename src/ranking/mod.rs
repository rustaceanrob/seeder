use std::{
    collections::HashMap,
    net::SocketAddr,
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
const RERUN_WEIGHT: f64 = 0.001;
const DNS_SAMPLE_SIZE: usize = 10;

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
            Some(PeerStatus::Failed((_, attempts))) => attempts + 1,
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
            PeerStatus::SuccessfulRun(_) => Some(RERUN_WEIGHT),
            _ => None,
        })
    }

    pub fn sample_successful(&self) -> Vec<SocketAddr> {
        let lock = self.addrs.lock().unwrap();
        let mut rng = rand::rng();
        let mut keyed: Vec<(f64, SocketAddr)> = lock
            .iter()
            .filter_map(|(addr, status)| match status {
                PeerStatus::SuccessfulRun(stats) => {
                    let weight = 1.0 / stats.time_elapsed.as_secs_f64().max(f64::EPSILON);
                    let key = rng.random::<f64>().powf(1.0 / weight);
                    Some((key, *addr))
                }
                _ => None,
            })
            .collect();
        keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        keyed.truncate(DNS_SAMPLE_SIZE);
        keyed.into_iter().map(|(_, addr)| addr).collect()
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
