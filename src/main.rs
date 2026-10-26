use std::{
    net::{SocketAddr, UdpSocket},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    crawler::{continuously_handshake, io::Timeouts, Connection},
    poller::continually_update_runs,
    ranking::AddressSet,
};

mod crawler;
mod dns;
mod poller;
mod ranking;

const CONFIG: dns::Configuration = dns::Configuration {
    hostname: "seeds.2140.dev",
    nameserver: "n1.2140.dev",
    hostmaster: "rob.2140.dev",
    ttl: 3600,
    query_answers: 5,
};

fn main() -> std::io::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let mut args = std::env::args();
    let _prog = args.next().unwrap();
    let seed_node = args
        .next()
        .expect("A seed node is required. Usage: cargo run -r <ip:port>");
    let socket_addr = seed_node.parse::<SocketAddr>().unwrap();
    let connection = Connection::config(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as i64,
    );
    tracing::info!("Seeding with {seed_node}");
    let (_, addrs) = connection
        .open(socket_addr, Timeouts::default())
        .expect("Seed connection failed!");
    tracing::info!("Seeded with {} network addresses", addrs.len());
    let set = AddressSet::default();
    set.add_gossiped(addrs);
    for id in 0..7 {
        let set = set.clone();
        std::thread::spawn(move || continuously_handshake(id, &set));
    }
    let set = set.clone();
    let snapshot = set.clone();
    std::thread::spawn(move || continually_update_runs(&set));
    let socket = UdpSocket::bind("0.0.0.0:53")?;
    tracing::info!("Listening on 0.0.0.0:53 for DNS queries");
    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) => {
                tracing::warn!("Failed to receive DNS query: {e}");
                continue;
            }
        };
        let sample = snapshot.sample_successful();
        let query = &buf[..len];
        let response_buf = match dns::build_reponse(query, CONFIG, &sample) {
            Ok(buf) => buf,
            Err(e) => {
                tracing::debug!("Dropping query from {src}: {e}");
                continue;
            }
        };
        if let Err(e) = socket.send_to(&response_buf, src) {
            tracing::warn!("Failed to respond to {src}: {e}");
        }
    }
}
