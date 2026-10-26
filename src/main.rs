use std::{
    net::UdpSocket,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    crawler::{continuously_handshake, io::Timeouts, Connection},
    dns::Configuration,
    poller::continually_update_runs,
    ranking::AddressSet,
};

mod crawler;
mod dns;
mod poller;
mod ranking;

configure_me::include_config!();

fn main() -> std::io::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    let dns_conf = Configuration {
        hostname: &config.hostname,
        nameserver: &config.nameserver,
        hostmaster: &config.hostmaster,
        ttl: config.ttl,
        query_answers: config.answers,
    };

    let connection = Connection::config(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as i64,
    );
    tracing::info!("Seeding with {}", config.seed_node);
    let (_, addrs) = connection
        .open(config.seed_node, Timeouts::default())
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
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", config.port))?;
    tracing::info!("Listening on 0.0.0.0:{} for DNS queries", config.port);
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
        let response_buf = match dns::build_reponse(query, &dns_conf, &sample) {
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
