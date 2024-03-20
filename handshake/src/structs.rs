//! Data structures and enums
use crate::codec::Codec;
use std::{fmt::Display, io::Write};

#[derive(Debug, Eq, PartialEq)]
pub enum ContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl ContentType {
    /// Write the encoding onto a buffer
    pub fn encode(&self, buffer: &mut impl Write) -> std::io::Result<usize> {
        let byte = match self {
            Self::Invalid => 0x00,
            Self::ChangeCipherSpec => 0x14,
            Self::Alert => 0x15,
            Self::Handshake => 0x16,
            Self::ApplicationData => 0x17,
        };
        buffer.write(&[byte])
    }

    /// Match a single byte into a ContentType
    pub fn from_byte(byte: &u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Invalid),
            0x14 => Some(Self::ChangeCipherSpec),
            0x15 => Some(Self::Alert),
            0x16 => Some(Self::Handshake),
            0x17 => Some(Self::ApplicationData),
            _ => None,
        }
    }

    /// If the beginning of the buffer encodes a content type, return the content type and the rest
    /// of the buffer; else, return None
    pub fn extract(buffer: &[u8]) -> Option<(Self, &[u8])> {
        if buffer.len() == 0 {
            return None;
        }
        let content_type = Self::from_byte(buffer.get(0).expect("buffer is empty"));
        match content_type {
            Some(content_type) => {
                let rest = buffer.get(1..).expect("Buffer is empty");
                Some((content_type, rest))
            }
            None => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    Tls1_0, // 0x0301
    Tls1_1, // 0x0302
    Tls1_2, // 0x0303
    Tls1_3, // 0x0304
}

impl ProtocolVersion {
    /// Write the encoding onto the buffer
    pub fn encode(&self, buffer: &mut impl Write) -> std::io::Result<usize> {
        let bytes = match self {
            Self::Tls1_0 => [0x03, 0x01],
            Self::Tls1_1 => [0x03, 0x02],
            Self::Tls1_2 => [0x03, 0x03],
            Self::Tls1_3 => [0x03, 0x04],
        };
        buffer.write(&bytes)
    }

    /// If the beginning of the buffer encodes a protocol version, return the protocol version and
    /// the rest of the buffer; else, return None and the entire buffer
    pub fn extract(buffer: &[u8]) -> Option<(Self, &[u8])> {
        if buffer.len() < 2 {
            return None;
        }
        let encoding = buffer.get(0..2).expect("Buffer has fewer than 2 bytes");
        let rest = buffer.get(2..).expect("Buffer has fewer than 2 bytes");
        match encoding {
            &[0x03, 0x01] => Some((Self::Tls1_0, rest)),
            &[0x03, 0x02] => Some((Self::Tls1_1, rest)),
            &[0x03, 0x03] => Some((Self::Tls1_2, rest)),
            &[0x03, 0x04] => Some((Self::Tls1_3, rest)),
            _ => None,
        }
    }
}

impl Codec for u16 {
    type Data = u16;

    fn encode(&self, buffer: &mut impl Write) -> std::io::Result<usize> {
        buffer.write(&self.to_be_bytes())
    }

    fn extract(buffer: &[u8]) -> Option<(Self::Data, &[u8])> {
        match buffer.get(0..2) {
            Some(slice) => {
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(slice);
                let length = u16::from_be_bytes(bytes);
                let rest = buffer.get(2..).expect("insufficient buffer data");
                Some((length, rest))
            }
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct Record {
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    fragment: Vec<u8>,
}

impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content_type = format!("{:?}", self.content_type);
        let protocol_version = format!("{:?}", self.protocol_version);
        let fragment = format!("fragment: {} bytes", self.fragment.len());
        write!(f, "Record: {content_type}, {protocol_version}, {fragment}")?;

        return Ok(());
    }
}

impl Codec for Record {
    type Data = Self;

    fn encode(&self, buffer: &mut impl Write) -> std::io::Result<usize> {
        let mut written = 0;
        written += self.content_type.encode(buffer)?;
        written += self.protocol_version.encode(buffer)?;
        let datalen: u16 = self
            .fragment
            .len()
            .try_into()
            .expect("fragment has too much data");
        written += datalen.encode(buffer)?;
        written += buffer.write(&self.fragment)?;

        return std::io::Result::Ok(written);
    }

    fn extract(buffer: &[u8]) -> Option<(Self::Data, &[u8])> {
        // This is a lot of repetition, but let's not abstract things prematurely
        let (content_type, buffer) = match ContentType::extract(buffer) {
            Some((content_type, rest)) => (content_type, rest),
            None => return None,
        };

        let (protocol_version, buffer) = match ProtocolVersion::extract(buffer) {
            Some((protocol_version, rest)) => (protocol_version, rest),
            None => return None,
        };

        let (data_len, buffer) = match u16::extract(buffer) {
            Some((length, rest)) => (length as usize, rest),
            None => return None,
        };

        // insufficient data
        if buffer.len() < data_len {
            return None;
        }

        let fragment: Vec<u8> = buffer
            .get(0..data_len)
            .expect("buffer doesn't have enough data")
            .to_vec();
        let rest = buffer
            .get(data_len..)
            .expect("buffer doesn't have enough data");
        let record = Self {
            content_type,
            protocol_version,
            fragment,
        };

        Some((record, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_extraction() {
        let data = [
            0x16, // Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x04, // fragment contains 4 bytes
            0x00, 0x00, 0x00, 0x00, // the data
        ];
        let (record, _) = Record::extract(&data).unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.protocol_version, ProtocolVersion::Tls1_2);
        assert_eq!(record.fragment, vec![0u8; 4]);
    }
}
