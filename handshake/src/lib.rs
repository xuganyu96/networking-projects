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

// TODO: implement the Record type
