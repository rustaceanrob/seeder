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
