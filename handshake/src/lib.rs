use std::{error::Error, fmt::Debug, ops::Deref};

use vec::Vector;
pub mod vec;

#[derive(Debug)]
pub enum DeserializationError {
    /// The supplied byte array doesn't contain enough bytes to be deserialized
    /// e.g. decoding a ContentType requires a minimum of 1 bytes, but input slice is empty
    InsufficientData { expected: usize, found: usize },

    /// The bytes do not match any valid enum variants.
    /// e.g. there is no valid content type for the byte 0x18
    InvalidEnumEncoding,
}

impl DeserializationError {
    pub fn insufficient_data(expected: usize, found: usize) -> Self {
        Self::InsufficientData { expected, found }
    }
}

impl std::fmt::Display for DeserializationError {
    /// Display will behave just like Debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DeserializationError {}

/// Can deserialize from raw bytes
pub trait Deserializable: Sized {
    /// Read from the beginning of the buffer and try to parse the raw bytes into this data
    /// structure. If the parsing is successful, return the data structure and the number of bytes
    /// consumed. Otherwise, return the appropriate error.
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError>;
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl ContentType {
    pub const BYTES: usize = 1;
}

impl Deserializable for ContentType {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding = buffer
            .get(0)
            .ok_or(DeserializationError::insufficient_data(
                Self::BYTES,
                buffer.len(),
            ))?;
        let data = match *encoding {
            0 => Self::Invalid,
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => {
                return Err(DeserializationError::InvalidEnumEncoding);
            }
        };

        return Ok((data, Self::BYTES));
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ProtocolVersion {
    /// 0x0301
    Tls1_0,
    /// 0x0302
    Tls1_1,
    /// 0x0303
    Tls1_2,
    /// 0x0304
    Tls1_3,
}

impl ProtocolVersion {
    pub const BYTES: usize = 2;
}

impl Deserializable for ProtocolVersion {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding =
            buffer
                .get(0..Self::BYTES)
                .ok_or(DeserializationError::insufficient_data(
                    Self::BYTES,
                    buffer.len(),
                ))?;
        let version = match encoding {
            &[0x03, 0x04] => Self::Tls1_3,
            &[0x03, 0x03] => Self::Tls1_2,
            &[0x03, 0x02] => Self::Tls1_1,
            &[0x03, 0x01] => Self::Tls1_0,
            _ => {
                return Err(DeserializationError::InvalidEnumEncoding);
            }
        };

        return Ok((version, Self::BYTES));
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct U8(u8);

impl U8 {
    pub const BYTES: usize = 1;

    pub fn to_usize(&self) -> usize {
        self.0 as usize
    }
}

impl From<U8> for usize {
    fn from(value: U8) -> Self {
        value.to_usize()
    }
}

impl Deref for U8 {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializable for U8 {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding = buffer
            .get(0)
            .ok_or(DeserializationError::insufficient_data(
                Self::BYTES,
                buffer.len(),
            ))?;

        return Ok((U8(*encoding), Self::BYTES));
    }
}

/// A custom wrapper around the native u16 type, useful for implementing custom traits
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct U16(u16);

impl U16 {
    pub const BYTES: usize = 2;

    /// Will panic if the slice length is not exactly 2
    pub(crate) fn from_be_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(slice);
        let val = u16::from_be_bytes(bytes);
        return Self(val);
    }

    /// Convert to usize for indexing
    pub fn to_usize(&self) -> usize {
        return self.0 as usize;
    }
}

impl From<U16> for usize {
    fn from(value: U16) -> Self {
        value.to_usize()
    }
}

impl Deref for U16 {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializable for U16 {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding =
            buffer
                .get(0..Self::BYTES)
                .ok_or(DeserializationError::insufficient_data(
                    Self::BYTES,
                    buffer.len(),
                ))?;
        let val = Self::from_be_slice(encoding);

        return Ok((val, Self::BYTES));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordPayload {
    /// Copy the raw bytes over
    Opaque(Vec<u8>),

    /// A handshake message
    Handshake(HandshakeMessage),

    /// An application data message
    ApplicationData,

    /// An alert
    Alert,
}

impl RecordPayload {
    pub fn opaque_from_slice(bytes: &[u8]) -> Self {
        Self::Opaque(bytes.to_vec())
    }

    pub fn opaque(data: Vec<u8>) -> Self {
        Self::Opaque(data)
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub content_type: ContentType,
    pub legacy_record_version: ProtocolVersion,
    pub length: U16,
    pub payload: RecordPayload,
}

impl Record {
    pub fn new(
        content_type: ContentType,
        legacy_record_version: ProtocolVersion,
        length: U16,
        payload: RecordPayload,
    ) -> Self {
        Self {
            content_type,
            legacy_record_version,
            length,
            payload,
        }
    }
}

impl Deserializable for Record {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (content_type, content_type_size) = ContentType::try_deserialize(buffer)?;
        let buffer = buffer
            .get(content_type_size..)
            .expect("Unexpected buffer overflow");

        let (protocol_version, protocol_version_size) = ProtocolVersion::try_deserialize(buffer)?;
        let buffer = buffer
            .get(protocol_version_size..)
            .expect("Unexpected buffer overflow");

        let (length, length_size) = U16::try_deserialize(buffer)?;
        let buffer = buffer
            .get(length_size..)
            .expect("Unexpected buffer overflow");

        // TODO: implement other payload types
        let payload_slice =
            buffer
                .get(..length.into())
                .ok_or(DeserializationError::insufficient_data(
                    length.into(),
                    buffer.len(),
                ))?;
        let payload = match content_type {
            ContentType::Handshake => {
                let (msg, _) = HandshakeMessage::try_deserialize(payload_slice)?;
                RecordPayload::Handshake(msg)
            }
            _ => RecordPayload::opaque(payload_slice.to_vec()),
        };

        return Ok((
            Self::new(content_type, protocol_version, length, payload),
            content_type_size + protocol_version_size + length_size + length.to_usize(),
        ));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeType {
    /// 0x01
    ClientHello,
    // TODO: implement the rest
    Other,
}

impl HandshakeType {
    pub const BYTES: usize = 1;
}

impl Deserializable for HandshakeType {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding = buffer
            .get(0)
            .ok_or(DeserializationError::insufficient_data(
                Self::BYTES,
                buffer.len(),
            ))?;
        let msg_type = match *encoding {
            1 => Self::ClientHello,
            // TODO: implement the rest
            _ => {
                return Err(DeserializationError::InvalidEnumEncoding);
            }
        };

        return Ok((msg_type, Self::BYTES));
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct U24(u32);

impl U24 {
    pub const BYTES: usize = 3;

    pub fn from_be_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), Self::BYTES);
        let mut bytes = [0u8; 4];
        bytes.get_mut(1..4).unwrap().copy_from_slice(slice);
        return Self(u32::from_be_bytes(bytes));
    }

    pub fn to_usize(&self) -> usize {
        self.0 as usize
    }
}

impl From<U24> for usize {
    fn from(value: U24) -> Self {
        value.to_usize()
    }
}

impl Deserializable for U24 {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let slice = buffer
            .get(0..Self::BYTES)
            .ok_or(DeserializationError::insufficient_data(
                Self::BYTES,
                buffer.len(),
            ))?;
        let length = U24::from_be_slice(slice);
        return Ok((length, Self::BYTES));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessagePayload {
    Raw(Vec<u8>),
    ClientHello(ClientHelloPayload),
}

#[derive(Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    /// 0x1301
    TLS_AES_128_GCM_SHA256,
    /// 0x1302
    TLS_AES_256_GCM_SHA384,
    /// 0x1303
    TLS_CHACHA20_POLY1305_SHA256,

    /// The value holds the encoding; all Tls1.2 ciphers will be ignored
    UnsupportedSuite(u8, u8),
}

impl std::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSuite(b1, b2) => write!(f, "UnsupportedSuite(0x{:02X}{:02X})", b1, b2),
            Self::TLS_AES_128_GCM_SHA256 => write!(f, "TLS_AES_128_GCM_SHA256 (0x1301)"),
            Self::TLS_AES_256_GCM_SHA384 => write!(f, "TLS_AES_256_GCM_SHA384 (0x1302)"),
            Self::TLS_CHACHA20_POLY1305_SHA256 => {
                write!(f, "TLS_CHACHA20_POLY1305_SHA256 (0x1303)")
            }
        }
    }
}

impl CipherSuite {
    pub const BYTES: usize = 2;
}

impl Deserializable for CipherSuite {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let encoding =
            buffer
                .get(0..Self::BYTES)
                .ok_or(DeserializationError::insufficient_data(
                    Self::BYTES,
                    buffer.len(),
                ))?;
        let suite = match encoding {
            &[0x13, 0x01] => Self::TLS_AES_128_GCM_SHA256,
            &[0x13, 0x02] => Self::TLS_AES_256_GCM_SHA384,
            &[0x13, 0x03] => Self::TLS_CHACHA20_POLY1305_SHA256,
            _ => Self::UnsupportedSuite(encoding[0], encoding[1]),
        };
        return Ok((suite, Self::BYTES));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionType {
    /// Useful for capturing the raw value and debugging
    Opaque(U16),
}

impl Deserializable for ExtensionType {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (tag, tag_size) = U16::try_deserialize(buffer)?;
        Ok((Self::Opaque(tag), tag_size))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionPayload {
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    ext_type: ExtensionType,
    length: U16,
    payload: ExtensionPayload,
}

impl Deserializable for Extension {
    /// For now only parse to raw values; later on implement the individual extensions
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (ext_type, tag_size) = ExtensionType::try_deserialize(buffer)?;
        let buffer = buffer.get(tag_size..).expect("Unexpected out-of-bound");
        let (length, length_size) = U16::try_deserialize(buffer)?;
        let buffer = buffer.get(length_size..).expect("Unexpected out-of-bound");
        let data_slice = match buffer.get(0..(length.into())) {
            None => {
                return Err(DeserializationError::insufficient_data(
                    length.into(),
                    buffer.len(),
                ))
            }
            Some(slice) => slice,
        };
        let payload = ExtensionPayload::Opaque(data_slice.to_vec());

        return Ok((
            Extension {
                ext_type,
                length,
                payload,
            },
            tag_size + length_size + length.to_usize(),
        ));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Random([u8; 32]);

impl Random {
    pub const BYTES: usize = 32;

    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), Self::BYTES);
        let mut random = [0u8; 32];
        random.copy_from_slice(slice);
        return Self(random);
    }
}

impl Deserializable for Random {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let random = match buffer.get(..Self::BYTES) {
            None => {
                return Err(DeserializationError::insufficient_data(
                    Self::BYTES,
                    buffer.len(),
                ));
            }
            Some(slice) => Random::from_slice(slice),
        };

        return Ok((random, Self::BYTES));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientHelloPayload {
    /// Always 0x0303 (Tls1.2) for compatibility reason
    legacy_version: ProtocolVersion,

    /// 32 bytes of entropy
    random: Random,

    /// Always an empty list in TLS 1.3
    legacy_session_id: Vector<U8, U8>,

    cipher_suites: Vector<CipherSuite, U16>,

    legacy_compression_method: Vector<U8, U8>,

    extensions: Vector<Extension, U16>,
}

impl Deserializable for ClientHelloPayload {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (protocol_ver, protocol_ver_size) = ProtocolVersion::try_deserialize(buffer)?;
        assert_eq!(protocol_ver_size, 2);
        let buffer = buffer
            .get(protocol_ver_size..)
            .expect("Unexpected out-of-bound error");

        let (random, random_size) = Random::try_deserialize(buffer)?;
        assert_eq!(random_size, 32);
        let buffer = buffer
            .get(random_size..)
            .expect("Unexpected out-of-bound error");

        let (session_id, session_id_size) = Vector::<U8, U8>::try_deserialize(buffer)?;
        let buffer = buffer
            .get(session_id_size..)
            .expect("Unexpected out-of-bound error");

        let (cipher_suites, cipher_suites_size) =
            Vector::<CipherSuite, U16>::try_deserialize(buffer)?;
        let buffer = buffer
            .get(cipher_suites_size..)
            .expect("Unexpected out-of-bound error");

        let (compression, compression_size) = Vector::<U8, U8>::try_deserialize(buffer)?;
        let buffer = buffer
            .get(compression_size..)
            .expect("Unexpected out-of-bound error");

        let (ext, ext_size) = Vector::<Extension, U16>::try_deserialize(buffer)?;

        return Ok((
            Self {
                legacy_version: protocol_ver,
                random,
                legacy_session_id: session_id,
                cipher_suites,
                legacy_compression_method: compression,
                extensions: ext,
            },
            protocol_ver_size
                + random_size
                + session_id_size
                + cipher_suites_size
                + compression_size
                + ext_size,
        ));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeMessage {
    msg_type: HandshakeType,
    length: U24,
    payload: HandshakeMessagePayload,
}

impl Deserializable for HandshakeMessage {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (msg_type, msg_type_size) = HandshakeType::try_deserialize(buffer)?;
        let buffer = buffer.get(msg_type_size..).expect("Unexpected overflow");
        let (length, length_size) = U24::try_deserialize(buffer)?;
        let buffer = buffer.get(length_size..).expect("Unexpected overflow");
        let payload_slice =
            buffer
                .get(..length.to_usize())
                .ok_or(DeserializationError::insufficient_data(
                    length.to_usize(),
                    buffer.len(),
                ))?;
        let payload = match msg_type {
            HandshakeType::ClientHello => {
                let (client_hello_payload, _) = ClientHelloPayload::try_deserialize(payload_slice)?;
                HandshakeMessagePayload::ClientHello(client_hello_payload)
            }
            _ => HandshakeMessagePayload::Raw(payload_slice.to_vec()),
        };

        return Ok((
            Self {
                msg_type,
                length,
                payload,
            },
            msg_type_size + length_size + length.to_usize(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_HELLO_BYTES: [u8; 243] = [
        0x16, 0x03, 0x01, 0x00, 0xEE, 0x01, 0x00, 0x00, 0xEA, 0x03, 0x03, 0x30, 0x3E, 0xB7, 0xF6,
        0x6F, 0xAC, 0x63, 0x01, 0xFE, 0x65, 0x33, 0xB1, 0xB6, 0xCC, 0xBC, 0x63, 0x63, 0x67, 0x46,
        0x17, 0x6B, 0xEC, 0x1A, 0x47, 0x2B, 0xB3, 0x8C, 0xBE, 0xFC, 0x84, 0xAD, 0x11, 0x20, 0x3E,
        0x80, 0xEA, 0xAB, 0x85, 0x9A, 0xD5, 0x3C, 0x6B, 0xFA, 0x3A, 0xB3, 0x41, 0x41, 0x67, 0x41,
        0xF1, 0x0C, 0x5F, 0x5F, 0xCE, 0x12, 0x67, 0x05, 0xD5, 0xF3, 0xB4, 0x91, 0xC3, 0xED, 0x73,
        0x06, 0x00, 0x14, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0xC0, 0x2C, 0xC0, 0x2B, 0xCC, 0xA9,
        0xC0, 0x30, 0xC0, 0x2F, 0xCC, 0xA8, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x8D, 0x00, 0x0D, 0x00,
        0x16, 0x00, 0x14, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x08, 0x07, 0x08, 0x06, 0x08, 0x05,
        0x08, 0x04, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01, 0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0A, 0x00,
        0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01,
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20, 0xC9, 0x95, 0x87, 0x67, 0xE3,
        0x8D, 0x0D, 0x6E, 0xF9, 0x5A, 0x71, 0x97, 0xAE, 0xF7, 0x95, 0x23, 0x6A, 0x0E, 0xB3, 0x4B,
        0x30, 0x43, 0x9B, 0x93, 0xBF, 0xAF, 0x25, 0xAB, 0x75, 0xEF, 0x40, 0x10, 0x00, 0x23, 0x00,
        0x00, 0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x00, 0x00, 0x13, 0x00,
        0x11, 0x00, 0x00, 0x0E, 0x61, 0x70, 0x69, 0x2E, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2E,
        0x63, 0x6F, 0x6D,
    ];

    #[test]
    fn parse_client_hello() {
        let (record, consumed) = Record::try_deserialize(&CLIENT_HELLO_BYTES).unwrap();
        assert_eq!(consumed, 243);

        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version, ProtocolVersion::Tls1_0);
        assert_eq!(record.length, U16(0xee));

        let handshake_msg = match record.payload {
            RecordPayload::Handshake(msg) => msg,
            _ => panic!("Expected handshake message, found {:?}", record.payload),
        };
        assert_eq!(handshake_msg.msg_type, HandshakeType::ClientHello);
        assert_eq!(handshake_msg.length, U24(0x0000ea));

        let ch_payload = match handshake_msg.payload {
            HandshakeMessagePayload::ClientHello(payload) => payload,
            _ => panic!(
                "Expected ClientHelloPayload, found {:?}",
                handshake_msg.payload
            ),
        };
        assert_eq!(ch_payload.legacy_version, ProtocolVersion::Tls1_2);
        assert_eq!(
            ch_payload.random.0,
            [
                0x30, 0x3E, 0xB7, 0xF6, 0x6F, 0xAC, 0x63, 0x01, 0xFE, 0x65, 0x33, 0xB1, 0xB6, 0xCC,
                0xBC, 0x63, 0x63, 0x67, 0x46, 0x17, 0x6B, 0xEC, 0x1A, 0x47, 0x2B, 0xB3, 0x8C, 0xBE,
                0xFC, 0x84, 0xAD, 0x11
            ]
        );
        assert_eq!(ch_payload.legacy_session_id.len(), 32);
        // assert_eq!(ch_payload.legacy_session_id.elems_slice(), &[]);

        assert_eq!(ch_payload.cipher_suites.len(), 20);
        assert_eq!(
            ch_payload.cipher_suites.elems_slice(),
            &[
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite::UnsupportedSuite(0xC0, 0x2C),
                CipherSuite::UnsupportedSuite(0xC0, 0x2B),
                CipherSuite::UnsupportedSuite(0xCC, 0xA9),
                CipherSuite::UnsupportedSuite(0xC0, 0x30),
                CipherSuite::UnsupportedSuite(0xC0, 0x2F),
                CipherSuite::UnsupportedSuite(0xCC, 0xA8),
                CipherSuite::UnsupportedSuite(0x00, 0xFF),
            ]
        );
        assert_eq!(ch_payload.legacy_compression_method.len(), 1);
        assert_eq!(ch_payload.legacy_compression_method.elems_slice(), &[U8(0)]);
        assert_eq!(ch_payload.extensions.len(), 141);
        assert_eq!(ch_payload.extensions.elems_slice().len(), 10);
    }

    // TODO: test parsing bad inputs
    #[test]
    fn parse_record_to_raw_bytes() {
        let buffer = [0x16, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00];
        let (record, _) = Record::try_deserialize(&buffer).expect("Failed to deserialize");
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version, ProtocolVersion::Tls1_0);
        assert_eq!(record.length, U16(2));
        assert_eq!(record.payload, RecordPayload::opaque(vec![0u8; 2]));
    }

    #[test]
    fn u24_from_be_slice() {
        assert_eq!(U24::from_be_slice(&[0x00, 0x00, 0x00]), U24(0x00000000u32));
        assert_eq!(U24::from_be_slice(&[0x00, 0x00, 0xff]), U24(0x000000ffu32));
        assert_eq!(U24::from_be_slice(&[0x00, 0xff, 0xff]), U24(0x0000ffffu32));
        assert_eq!(U24::from_be_slice(&[0xff, 0xff, 0xff]), U24(0x00ffffffu32));
    }

    #[test]
    fn parse_empty_handshake_message() {
        let buffer = [0x01, 0x00, 0x00, 0x00];
        let (msg, _) = HandshakeMessage::try_deserialize(&buffer).expect("Failed to deserialize");
        assert_eq!(
            msg,
            HandshakeMessage {
                msg_type: HandshakeType::ClientHello,
                length: U24(0),
                payload: HandshakeMessagePayload::Raw(vec![])
            }
        );
    }

    #[test]
    fn parse_nonempty_handshake_raw() {
        let buffer = [0x01, 0x00, 0x00, 0x01, 0xff];
        let (msg, _) = HandshakeMessage::try_deserialize(&buffer).expect("Failed to deserialize");
        assert_eq!(
            msg,
            HandshakeMessage {
                msg_type: HandshakeType::ClientHello,
                length: U24(1),
                payload: HandshakeMessagePayload::Raw(vec![0xff])
            }
        );
    }
}
