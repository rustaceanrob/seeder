use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime},
};

use bip157::{tokio, BlockHash, Builder, Client, Event, HashCheckpoint, Info, Receiver, Warning};
use bip324::Network;

use crate::ranking::AddressSet;

pub const START_HASH: &str = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054";
pub const START_HEIGHT: u32 = 800_000;
pub const STOP_HASH: &str = "000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a";
pub const MAX_SYNC_TIME: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Copy)]
pub struct RunStats {
    pub time_elapsed: Duration,
    pub when: SystemTime,
}

pub fn continually_update_runs(addresses: &AddressSet) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime required");
    loop {
        let random = addresses.sample_for_run();
        match random {
            Some(socket_addr) => match download_filter_range(&rt, socket_addr) {
                Ok(stats) => {
                    tracing::info!(
                        "Successful run with {socket_addr}. Took {} seconds",
                        stats.time_elapsed.as_secs()
                    );
                    addresses.successful_run(socket_addr, stats);
                }
                Err(_) => {
                    tracing::warn!("Failed run with {socket_addr}");
                    addresses.failed_run(socket_addr);
                }
            },
            None => std::thread::sleep(Duration::from_secs(5)),
        }
    }
}

pub fn download_filter_range(
    rt: &tokio::runtime::Runtime,
    addr: SocketAddr,
) -> Result<RunStats, std::io::Error> {
    let from = HashCheckpoint::new(START_HEIGHT, STOP_HASH.parse::<BlockHash>().unwrap());
    let to = STOP_HASH.parse::<BlockHash>().unwrap();
    let result = rt.block_on(tokio::time::timeout(
        MAX_SYNC_TIME,
        build_and_download(addr, from, to),
    ));
    if let Ok(Ok(stats)) = result {
        return Ok(stats);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Node process timed out.",
    ))
}

async fn build_and_download(
    addr: SocketAddr,
    from: HashCheckpoint,
    to: BlockHash,
) -> Result<RunStats, std::io::Error> {
    let (node, client) = Builder::new(Network::Bitcoin)
        .add_peer(addr)
        .chain_state(bip157::ChainState::Checkpoint(from))
        .whitelist_only()
        .build();
    let Client {
        requester,
        info_rx,
        warn_rx,
        mut event_rx,
    } = client;

    tokio::task::spawn(async move { trace_logs(info_rx, warn_rx).await });
    let then = Instant::now();
    tokio::task::spawn(async move { node.run().await });
    loop {
        match event_rx.recv().await {
            Some(Event::IndexedFilter(filter)) => {
                if filter.block_hash() == to {
                    break;
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unexpected end of sync",
                ))
            }
            _ => (),
        }
    }
    let _ = requester.average_fee_rate(to).await;
    Ok(RunStats {
        time_elapsed: then.elapsed(),
        when: SystemTime::now(),
    })
}

async fn trace_logs(mut info_rx: Receiver<Info>, mut warn_rx: Receiver<Warning>) {
    loop {
        tokio::select! {
            warn = warn_rx.recv() => {
                if let Some(warn) = warn {
                    tracing::debug!("{warn}")
                }
            }
            info = info_rx.recv() => {
                if let Some(info) = info {
                    tracing::debug!("{info}")
                }
            }
        }
    }
}
