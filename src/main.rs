use std::{
    net::SocketAddr,
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

fn main() {
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
    let set = AddressSet::default();
    set.add_gossiped(addrs);
    for id in 0..7 {
        let set = set.clone();
        std::thread::spawn(move || continuously_handshake(id, &set));
    }
    let set = set.clone();
    let thread = std::thread::spawn(move || continually_update_runs(&set));
    let _ = thread.join();
    tracing::error!("Shutting down");
}
