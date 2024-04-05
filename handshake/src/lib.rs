use std::{error::Error, ops::Deref};

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
pub(crate) trait Deserializable: Sized {
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
    Tls1_0,
    Tls1_1,
    Tls1_2,
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
    Raw(Vec<u8>),

    /// A handshake message
    Handshake(HandshakeMessage),

    /// An application data message
    ApplicationData,

    /// An alert
    Alert,
}

impl RecordPayload {
    pub fn from_raw_slice(bytes: &[u8]) -> Self {
        Self::Raw(bytes.to_vec())
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
        let mut bytes_parsed: usize = 0;
        let (content_type, consumed) = ContentType::try_deserialize(buffer)?;
        let buffer = buffer.get(consumed..).expect("Unexpected buffer overflow");
        bytes_parsed += consumed;

        let (protocol_version, consumed) = ProtocolVersion::try_deserialize(buffer)?;
        let buffer = buffer.get(consumed..).expect("Unexpected buffer overflow");
        bytes_parsed += consumed;

        let (length, consumed) = U16::try_deserialize(buffer)?;
        let buffer = buffer.get(consumed..).expect("Unexpected buffer overflow");
        bytes_parsed += consumed;

        // TODO: for now we will only parse to raw bytes; after individual message type is
        //   implemented, should parse to the correct message type
        let length_usize = length.to_usize();
        let buffer = buffer
            .get(0..length_usize)
            .ok_or(DeserializationError::insufficient_data(
                length_usize,
                buffer.len(),
            ))?;
        let fragment = RecordPayload::from_raw_slice(buffer);
        bytes_parsed += length.to_usize();
        let record = Self::new(content_type, protocol_version, length, fragment);
        return Ok((record, bytes_parsed));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeType {
    /// 0x01
    ClientHello,
    // TODO: implement the rest
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
    ClientHelloPayload,
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
        let payload =
            buffer
                .get(..length.to_usize())
                .ok_or(DeserializationError::insufficient_data(
                    length.to_usize(),
                    buffer.len(),
                ))?;
        // TODO: parse the payload instead of just raw
        let payload = HandshakeMessagePayload::Raw(payload.to_vec());

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

    // TODO: test parsing bad inputs
    #[test]
    fn parse_record_to_raw_bytes() {
        let buffer = [0x16, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00];
        let (record, _) = Record::try_deserialize(&buffer).expect("Failed to deserialize");
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.legacy_record_version, ProtocolVersion::Tls1_0);
        assert_eq!(record.length, U16(2));
        assert_eq!(record.payload, RecordPayload::from_raw_slice(&[0u8; 2]));
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
