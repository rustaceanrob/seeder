use core::option::Option;
use std::{marker::PhantomData, net::SocketAddr};

use bip324::serde::NetworkMessage;
use bitcoin::p2p::{message_network::VersionMessage, ServiceFlags};

pub struct Unitialized;

pub struct VersionReceived;

pub struct VerackReceived;

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for Unitialized {}
impl sealed::Sealed for VersionReceived {}
impl sealed::Sealed for VerackReceived {}

pub trait State: sealed::Sealed {}

impl State for Unitialized {}
impl State for VersionReceived {}
impl State for VerackReceived {}

pub enum ProcessNegotiation {
    Continue(Handshake<VersionReceived>),
    Completed(Handshake<VerackReceived>),
}

pub enum ProcessAddresses {
    Continue(Handshake<VerackReceived>),
    SendPong(Handshake<VerackReceived>, u64),
    Completed((ServiceFlags, Vec<SocketAddr>)),
}

pub struct Handshake<S: State> {
    version: Option<VersionMessage>,
    addrs: Vec<SocketAddr>,
    _marker: PhantomData<S>,
}

impl Handshake<Unitialized> {
    pub fn new() -> Handshake<Unitialized> {
        Self {
            version: None,
            addrs: Vec::with_capacity(1_000),
            _marker: PhantomData,
        }
    }

    pub fn process_message(
        self,
        message: NetworkMessage,
    ) -> Result<Handshake<VersionReceived>, std::io::Error> {
        if let NetworkMessage::Version(version) = message {
            return Ok(Handshake {
                version: Some(version),
                addrs: self.addrs,
                _marker: PhantomData,
            });
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Version message must be first.",
        ))
    }
}

impl Handshake<VersionReceived> {
    pub fn process_message(
        self,
        message: NetworkMessage,
    ) -> Result<ProcessNegotiation, std::io::Error> {
        match message {
            NetworkMessage::Verack => Ok(ProcessNegotiation::Completed(Handshake {
                version: self.version,
                addrs: self.addrs,
                _marker: PhantomData,
            })),
            NetworkMessage::SendHeaders
            | NetworkMessage::SendAddrV2
            | NetworkMessage::WtxidRelay
            | NetworkMessage::SendCmpct(_)
            | NetworkMessage::FeeFilter(_) => Ok(ProcessNegotiation::Continue(self)),
            msg => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unexpected message received {}", msg.cmd()),
            )),
        }
    }
}

impl Handshake<VerackReceived> {
    pub fn process_message(
        mut self,
        message: NetworkMessage,
    ) -> Result<ProcessAddresses, std::io::Error> {
        match message {
            NetworkMessage::AddrV2(entries) => {
                self.addrs.extend(
                    entries
                        .into_iter()
                        .filter_map(|entry| entry.socket_addr().ok()),
                );
                Ok(ProcessAddresses::Completed((
                    self.version.unwrap().services,
                    self.addrs,
                )))
            }
            NetworkMessage::Ping(ping) => Ok(ProcessAddresses::SendPong(self, ping)),
            NetworkMessage::Version(_)
            | NetworkMessage::Verack
            | NetworkMessage::FilterLoad(_)
            | NetworkMessage::FilterAdd(_)
            | NetworkMessage::FilterClear
            | NetworkMessage::MerkleBlock(_)
            | NetworkMessage::GetCFilters(_)
            | NetworkMessage::CFilter(_)
            | NetworkMessage::GetCFHeaders(_)
            | NetworkMessage::CFHeaders(_)
            | NetworkMessage::GetCFCheckpt(_)
            | NetworkMessage::CFCheckpt(_)
            | NetworkMessage::MemPool => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected message",
            )),
            _ => Ok(ProcessAddresses::Continue(self)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};

    fn version(services: ServiceFlags) -> NetworkMessage {
        let mut version = crate::crawler::Connection::config(0).us;
        version.services = services;
        NetworkMessage::Version(version)
    }

    fn negotiated(services: ServiceFlags) -> Handshake<VerackReceived> {
        let handshake = Handshake::new().process_message(version(services)).unwrap();
        match handshake.process_message(NetworkMessage::Verack).unwrap() {
            ProcessNegotiation::Completed(handshake) => handshake,
            ProcessNegotiation::Continue(_) => panic!("verack must complete negotiation"),
        }
    }

    fn addr_v2(addr: AddrV2, port: u16) -> AddrV2Message {
        AddrV2Message {
            time: 0,
            services: ServiceFlags::NONE,
            addr,
            port,
        }
    }

    #[test]
    fn version_must_be_first() {
        for message in [
            NetworkMessage::Verack,
            NetworkMessage::SendAddrV2,
            NetworkMessage::Ping(1),
        ] {
            assert!(Handshake::new().process_message(message).is_err());
        }
    }

    #[test]
    fn negotiation_messages_continue_until_verack() {
        let mut handshake = Handshake::new()
            .process_message(version(ServiceFlags::NONE))
            .unwrap();
        for message in [
            NetworkMessage::SendHeaders,
            NetworkMessage::SendAddrV2,
            NetworkMessage::WtxidRelay,
            NetworkMessage::FeeFilter(1_000),
        ] {
            handshake = match handshake.process_message(message).unwrap() {
                ProcessNegotiation::Continue(handshake) => handshake,
                ProcessNegotiation::Completed(_) => panic!("only verack completes negotiation"),
            };
        }
        assert!(matches!(
            handshake.process_message(NetworkMessage::Verack).unwrap(),
            ProcessNegotiation::Completed(_)
        ));
    }

    #[test]
    fn unexpected_message_during_negotiation_fails() {
        let handshake = Handshake::new()
            .process_message(version(ServiceFlags::NONE))
            .unwrap();
        assert!(handshake.process_message(NetworkMessage::GetAddr).is_err());
        let handshake = Handshake::new()
            .process_message(version(ServiceFlags::NONE))
            .unwrap();
        assert!(handshake
            .process_message(version(ServiceFlags::NONE))
            .is_err());
    }

    #[test]
    fn ping_after_verack_requests_pong() {
        let handshake = negotiated(ServiceFlags::NONE);
        match handshake.process_message(NetworkMessage::Ping(42)).unwrap() {
            ProcessAddresses::SendPong(_, nonce) => assert_eq!(nonce, 42),
            _ => panic!("ping must request a pong"),
        }
    }

    #[test]
    fn unrelated_messages_after_verack_continue() {
        let mut handshake = negotiated(ServiceFlags::NONE);
        for message in [
            NetworkMessage::SendHeaders,
            NetworkMessage::FeeFilter(1_000),
            NetworkMessage::Addr(Vec::new()),
            NetworkMessage::Pong(1),
        ] {
            handshake = match handshake.process_message(message).unwrap() {
                ProcessAddresses::Continue(handshake) => handshake,
                _ => panic!("message should be ignored"),
            };
        }
    }

    #[test]
    fn protocol_violations_after_verack_fail() {
        for message in [
            version(ServiceFlags::NONE),
            NetworkMessage::Verack,
            NetworkMessage::MemPool,
            NetworkMessage::FilterClear,
        ] {
            assert!(negotiated(ServiceFlags::NONE)
                .process_message(message)
                .is_err());
        }
    }

    #[test]
    fn addrv2_completes_with_peer_services_and_ip_addresses() {
        let services = ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS;
        let handshake = negotiated(services);
        let entries = vec![
            addr_v2(AddrV2::Ipv4("1.2.3.4".parse().unwrap()), 8333),
            addr_v2(AddrV2::TorV3([7; 32]), 8333),
            addr_v2(AddrV2::Ipv6("2001:db8::1".parse().unwrap()), 8334),
        ];
        match handshake
            .process_message(NetworkMessage::AddrV2(entries))
            .unwrap()
        {
            ProcessAddresses::Completed((flags, addrs)) => {
                assert_eq!(flags, services);
                assert_eq!(
                    addrs,
                    vec![
                        "1.2.3.4:8333".parse::<SocketAddr>().unwrap(),
                        "[2001:db8::1]:8334".parse().unwrap(),
                    ]
                );
            }
            _ => panic!("addrv2 must complete the handshake"),
        }
    }
}
