//! Handshake Extensions
use crate::primitives::U16;
use crate::traits::{Deserializable, DeserializationError};
use crate::UNEXPECTED_OUT_OF_BOUND_PANIC;
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionType {
    /// Both for testing and for accommodating unsupported extension types
    Opaque([u8; Self::BYTES]),
}

impl ExtensionType {
    pub const BYTES: usize = 2;
    pub const TESTING: Self = Self::Opaque([0xFF, 0xFF]);

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Opaque(encoding) => encoding.clone(),
        }
    }
}

impl Deserializable for ExtensionType {
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let encoding = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let extension_type = match *encoding {
            _ => Self::Opaque([encoding[0], encoding[1]]),
        };

        Ok((extension_type, Self::BYTES))
    }

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionPayload {
    Opaque(Vec<u8>),
}

impl Deserializable for ExtensionPayload {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
        }
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let fragment = buf.to_vec();
        Ok((Self::Opaque(fragment), buf.len()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    extension_type: ExtensionType,
    length: U16,
    payload: ExtensionPayload,
}

impl Deserializable for Extension {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let type_size = self.extension_type.serialize(buf)?;
        buf = buf
            .get_mut(type_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let length_size = self.length.serialize(buf)?;
        buf = buf
            .get_mut(length_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let payload_size = self.payload.serialize(buf)?;

        Ok(type_size + length_size + payload_size)
    }

    fn deserialize(mut buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let static_size = ExtensionType::BYTES + U16::BYTES;
        if buf.len() < static_size {
            return Err(DeserializationError::insufficient_buffer_length(
                static_size,
                buf.len(),
            ));
        }
        let (extension_type, type_size) = ExtensionType::deserialize(buf)?;
        buf = buf.get(type_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (length, length_size) = U16::deserialize(buf)?;
        buf = buf.get(length_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let length_usize: usize = length.into();

        if buf.len() < length_usize {
            return Err(DeserializationError::insufficient_vec_data(
                length_usize,
                buf.len(),
            ));
        }
        let data_slice = buf
            .get(..length_usize)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let payload = match extension_type {
            ExtensionType::Opaque(_) => ExtensionPayload::Opaque(data_slice.to_vec()),
        };

        return Ok((
            Self {
                extension_type,
                length,
                payload,
            },
            type_size + length_size + length_usize,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_extension_serde() {
        let expected_buf = [0xFF, 0xFF, 0x00, 0x00];
        let expected_extension = Extension {
            extension_type: ExtensionType::TESTING,
            length: U16(0),
            payload: ExtensionPayload::Opaque(vec![]),
        };

        let mut buf = [0u8; 4];
        expected_extension.serialize(&mut buf).unwrap();
        assert_eq!(buf, expected_buf);
        assert_eq!(
            Extension::deserialize(&expected_buf),
            Ok((expected_extension, 4))
        );
    }
}
