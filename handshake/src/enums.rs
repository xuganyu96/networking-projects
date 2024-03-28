//! A collection of simple enums that directly encode into one or two bytes
use crate::codec::{Codec, DecodeError};

#[derive(Debug, PartialEq)]
pub enum ContentType {
    Invalid,  // 0x01
    ChangeCipherSpec,  // 0x14
    Alert,  // 0x15
    Handshake,  // 0x16
    ApplicationData,  // 0x17
}

impl Codec for ContentType {
    type Data = Self;

    fn encode_size(&self) -> usize {
        1
    }

    fn encode_to_bytes(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        todo!();
    }

    fn extract(buffer: &[u8]) -> Result<(Self::Data, &[u8]), DecodeError> {
        todo!();
    }
}

pub enum ProtocolVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}
