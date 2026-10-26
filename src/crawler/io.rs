use std::{
    io::{BufReader, BufWriter},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use bip324::{
    io::{Payload, Protocol},
    serde::NetworkMessage,
    PacketType, Role,
};
use bitcoin::p2p::ServiceFlags;

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

impl Connection {
    pub fn open(
        &self,
        socket_addr: SocketAddr,
        timeouts: Timeouts,
    ) -> Result<(ServiceFlags, Vec<SocketAddr>), std::io::Error> {
        let tcp_stream = TcpStream::connect_timeout(&socket_addr, timeouts.tcp)?;
        tcp_stream.set_write_timeout(Some(timeouts.write))?;
        tcp_stream.set_read_timeout(Some(timeouts.read))?;
        let reader = BufReader::new(tcp_stream.try_clone()?);
        let writer = BufWriter::new(tcp_stream);
        let mut protocol = Protocol::new(
            bip324::Network::Bitcoin,
            Role::Initiator,
            None,
            None,
            reader,
            writer,
        )
        .map_err(|e| std::io::Error::other(format!("bip324 handshake: {e}")))?;
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
        protocol: &mut Protocol<BufReader<TcpStream>, BufWriter<TcpStream>>,
        message: NetworkMessage,
    ) -> Result<(), std::io::Error> {
        let contents = bip324::serde::serialize(message);
        protocol
            .write(&Payload::genuine(contents))
            .map_err(|e| std::io::Error::other(format!("write_message: {e}")))?;
        Ok(())
    }

    fn read_message(
        protocol: &mut Protocol<BufReader<TcpStream>, BufWriter<TcpStream>>,
    ) -> Result<NetworkMessage, std::io::Error> {
        let message = protocol
            .read()
            .map_err(|e| std::io::Error::other(format!("read_message: {e}")))?;
        match message.packet_type() {
            PacketType::Genuine => Ok(bip324::serde::deserialize(message.contents())
                .map_err(|e| std::io::Error::other(e.to_string()))?),
            PacketType::Decoy => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected decoy packet.",
            )),
        }
    }
}
