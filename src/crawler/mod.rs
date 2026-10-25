use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::p2p::{message_network::VersionMessage, Address, ServiceFlags};

use crate::{crawler::io::Timeouts, ranking::AddressSet};

pub mod handshake;
pub mod io;

const PLACEHOLDER_ADDR: std::net::SocketAddr =
    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
const USER_AGENT: &str = "bitcoin-seeder:0.1.0/rust-bitcoin:0.32";
const PROTOCOL_VERSION: u32 = 70016;

pub struct Connection {
    us: VersionMessage,
}

impl Connection {
    pub fn config(timestamp: i64) -> Connection {
        Self {
            us: VersionMessage {
                version: PROTOCOL_VERSION,
                services: ServiceFlags::NONE,
                timestamp,
                receiver: Address::new(&PLACEHOLDER_ADDR, ServiceFlags::NONE),
                sender: Address::new(&PLACEHOLDER_ADDR, ServiceFlags::NONE),
                nonce: 0,
                user_agent: USER_AGENT.to_string(),
                start_height: 0,
                relay: false,
            },
        }
    }
}

pub fn continuously_handshake(id: usize, addresses: &AddressSet) {
    loop {
        let addr = addresses.sample_for_handshake();
        match addr {
            Some(addr) => {
                tracing::info!("[thread {id}]: Attempting handshake with {addr}");
                let result = Connection::config(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards.")
                        .as_secs() as i64,
                )
                .open(addr, Timeouts::default());
                match result {
                    Ok((flags, addrs)) => {
                        tracing::info!(
                            "[thread {id}]: Recevied {} network addresses.",
                            addrs.len()
                        );
                        addresses.add_gossiped(addrs);
                        if flags.has(ServiceFlags::COMPACT_FILTERS) {
                            tracing::info!("[thread {id}]: {addr} services compact filters.",);
                            addresses.successful_handshake(addr);
                        } else {
                            tracing::warn!("[thread {id}]: {addr} does not serve compact filters.",);
                            addresses.unsupported(addr);
                        }
                    }
                    Err(e) => {
                        tracing::error!("[thread {id}]: {e}");
                        addresses.failed_handshake(addr);
                    }
                }
            }
            None => {
                tracing::warn!(
                    "[thread {id}]: No addresses available for handshake. Retrying in 5s."
                );
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}
