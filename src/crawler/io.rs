use std::{
    io::{BufReader, BufWriter, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use bitcoin::{
    consensus::{encode, Decodable},
    p2p::{
        message::{NetworkMessage, RawNetworkMessage},
        Magic, ServiceFlags,
    },
};

use crate::crawler::{
    handshake::{Handshake, ProcessAddresses, ProcessNegotiation},
    Connection,
};

pub struct Timeouts {
    tcp: Duration,
    read: Duration,
    write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tcp: Duration::from_secs(10),
            read: Duration::from_secs(10),
            write: Duration::from_secs(10),
        }
    }
}

pub struct Protocol {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl Connection {
    pub fn open(
        &self,
        socket_addr: SocketAddr,
        timeouts: Timeouts,
    ) -> Result<(ServiceFlags, Vec<SocketAddr>), std::io::Error> {
        let tcp_stream = TcpStream::connect_timeout(&socket_addr, timeouts.tcp)?;
        tcp_stream.set_write_timeout(Some(timeouts.write))?;
        tcp_stream.set_read_timeout(Some(timeouts.read))?;
        let mut protocol = Protocol {
            reader: BufReader::new(tcp_stream.try_clone()?),
            writer: BufWriter::new(tcp_stream),
        };
        let handshake = Handshake::new();
        Self::write_message(&mut protocol, NetworkMessage::Version(self.us.clone()))?;
        Self::write_message(&mut protocol, NetworkMessage::SendAddrV2)?;
        let message = Self::read_message(&mut protocol)?;
        let mut version_accepted = handshake.process_message(message)?;
        let mut verack = loop {
            let message = Self::read_message(&mut protocol)?;
            match version_accepted.process_message(message)? {
                ProcessNegotiation::Completed(verack_received) => break verack_received,
                ProcessNegotiation::Continue(handshake) => version_accepted = handshake,
            }
        };
        Self::write_message(&mut protocol, NetworkMessage::Verack)?;
        Self::write_message(&mut protocol, NetworkMessage::GetAddr)?;
        let (services, addrs) = loop {
            let message = Self::read_message(&mut protocol)?;
            match verack.process_message(message)? {
                ProcessAddresses::Continue(con) => verack = con,
                ProcessAddresses::SendPong(con, ping) => {
                    Self::write_message(&mut protocol, NetworkMessage::Pong(ping))?;
                    verack = con;
                }
                ProcessAddresses::Completed(tup) => break tup,
            }
        };
        Ok((services, addrs))
    }

    fn write_message(
        protocol: &mut Protocol,
        message: NetworkMessage,
    ) -> Result<(), std::io::Error> {
        let raw = RawNetworkMessage::new(Magic::BITCOIN, message);
        protocol.writer.write_all(&encode::serialize(&raw))?;
        protocol.writer.flush()
    }

    fn read_message(protocol: &mut Protocol) -> Result<NetworkMessage, std::io::Error> {
        let raw =
            RawNetworkMessage::consensus_decode(bitcoin::io::from_std_mut(&mut protocol.reader))
                .map_err(|e| std::io::Error::other(format!("read_message: {e}")))?;
        if *raw.magic() != Magic::BITCOIN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "read_message: wrong network magic",
            ));
        }
        Ok(raw.into_payload())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread::JoinHandle};

    use bitcoin::p2p::address::{AddrV2, AddrV2Message};

    fn short_timeouts() -> Timeouts {
        Timeouts {
            tcp: Duration::from_secs(2),
            read: Duration::from_secs(2),
            write: Duration::from_secs(2),
        }
    }

    fn send(protocol: &mut Protocol, message: NetworkMessage) {
        Connection::write_message(protocol, message).unwrap();
    }

    fn recv(protocol: &mut Protocol) -> NetworkMessage {
        Connection::read_message(protocol).unwrap()
    }

    fn fake_peer<T: Send + 'static>(
        script: impl FnOnce(&mut Protocol) -> T + Send + 'static,
    ) -> (SocketAddr, JoinHandle<T>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut protocol = Protocol {
                reader: BufReader::new(stream.try_clone().unwrap()),
                writer: BufWriter::new(stream),
            };
            script(&mut protocol)
        });
        (addr, handle)
    }

    fn peer_version(services: ServiceFlags) -> NetworkMessage {
        let mut version = Connection::config(0).us;
        version.services = services;
        NetworkMessage::Version(version)
    }

    fn gossip() -> Vec<AddrV2Message> {
        vec![AddrV2Message {
            time: 0,
            services: ServiceFlags::NONE,
            addr: AddrV2::Ipv4("1.2.3.4".parse().unwrap()),
            port: 8333,
        }]
    }

    #[test]
    fn open_completes_handshake_and_collects_addresses() {
        let services = ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS;
        let (addr, peer) = fake_peer(move |protocol| {
            let mut received = vec![recv(protocol), recv(protocol)];
            send(protocol, peer_version(services));
            send(protocol, NetworkMessage::SendAddrV2);
            send(protocol, NetworkMessage::WtxidRelay);
            send(protocol, NetworkMessage::Verack);
            received.push(recv(protocol));
            received.push(recv(protocol));
            send(protocol, NetworkMessage::SendHeaders);
            send(protocol, NetworkMessage::Ping(7));
            received.push(recv(protocol));
            send(protocol, NetworkMessage::AddrV2(gossip()));
            received
        });
        let (flags, addrs) = Connection::config(0).open(addr, short_timeouts()).unwrap();
        assert_eq!(flags, services);
        assert_eq!(addrs, vec!["1.2.3.4:8333".parse::<SocketAddr>().unwrap()]);
        let received = peer.join().unwrap();
        assert!(matches!(received[0], NetworkMessage::Version(_)));
        assert_eq!(received[1], NetworkMessage::SendAddrV2);
        assert_eq!(received[2], NetworkMessage::Verack);
        assert_eq!(received[3], NetworkMessage::GetAddr);
        assert_eq!(received[4], NetworkMessage::Pong(7));
    }

    #[test]
    fn open_fails_when_peer_disconnects() {
        let (addr, peer) = fake_peer(|protocol| {
            recv(protocol);
            recv(protocol);
            send(protocol, peer_version(ServiceFlags::COMPACT_FILTERS));
        });
        assert!(Connection::config(0).open(addr, short_timeouts()).is_err());
        peer.join().unwrap();
    }

    #[test]
    fn open_fails_when_version_is_not_first() {
        let (addr, peer) = fake_peer(|protocol| {
            recv(protocol);
            recv(protocol);
            send(protocol, NetworkMessage::Verack);
        });
        assert!(Connection::config(0).open(addr, short_timeouts()).is_err());
        peer.join().unwrap();
    }

    #[test]
    fn open_fails_without_a_listener() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(Connection::config(0).open(addr, short_timeouts()).is_err());
    }
}
