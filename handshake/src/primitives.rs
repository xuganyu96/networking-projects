use crate::{
    traits::{Deserializable, DeserializationError},
    UNEXPECTED_OUT_OF_BOUND_PANIC,
};
use std::io::Write;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U8(u8);

impl U8 {
    pub const BYTES: usize = 1;
}

impl Deserializable for U8 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        return Ok((Self(buf[0]), Self::BYTES));
    }
}

impl From<U8> for usize {
    fn from(value: U8) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U16(u16);

impl U16 {
    pub const BYTES: usize = 2;
}

impl Deserializable for U16 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u16::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl From<U16> for usize {
    fn from(value: U16) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U24(u32);

impl U24 {
    pub const BYTES: usize = 3;
}

impl Deserializable for U24 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    /// Only read the first three bytes from the input buffer and parses them into a u32
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; 4];
        be_bytes
            .get_mut(1..4)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
            .copy_from_slice(&buf[0..Self::BYTES]);
        let val = u32::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U24 {
    fn into(self) -> usize {
        self.0.try_into().expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U32(u32);

impl U32 {
    pub const BYTES: usize = 4;
}

impl Deserializable for U32 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u32::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U32 {
    fn into(self) -> usize {
        self.0.try_into().expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U64(u64);

impl U64 {
    pub const BYTES: usize = 8;
}

impl Deserializable for U64 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u64::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U64 {
    fn into(self) -> usize {
        self.0.try_into().expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
    }
}

/// T is the length type; U is the element type
pub struct Vector<T, U> {
    /// The number of bytes needed to serialize and deserialize the vector
    size: T,
    /// The individual elements
    elems: Vec<U>,
}

impl<T, U> Vector<T, U> {
    pub fn elems_slice(&self) -> &[U] {
        &self.elems
    }
}

impl<T, U> Deserializable for Vector<T, U>
where
    T: Deserializable + Copy,
    U: Deserializable,
    usize: From<T>, // TODO: is it better to qualify with Into<usize>?
{
    /// First serialize the size, then serialize the data
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        // TODO: need to check that buf actually has enough lenth left
        written += self.size.serialize(&mut buf[written..])?;
        for elem in self.elems_slice() {
            written += elem.serialize(&mut buf[written..])?;
        }
        return Ok(written);
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let mut written: usize = 0;
        let (datalen, consumed) = T::deserialize(buf)?;
        let datalen_usize: usize = datalen.into();
        written += datalen_usize;
        let mut dataslice = &buf[consumed..consumed + datalen_usize];

        if dataslice.len() < datalen_usize {
            return Err(DeserializationError::insufficient_vec_data(
                datalen_usize,
                dataslice.len(),
            ));
        }

        let mut elems: Vec<U> = vec![];
        while dataslice.len() > 0 {
            let (elem, elem_size) = U::deserialize(dataslice)?;
            elems.push(elem);
            dataslice = &dataslice[elem_size..];
        }

        let vector = Self {
            size: datalen,
            elems,
        };

        Ok((vector, written))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// 0x00
    Invalid,
    /// 0x14
    ChangeCipherSpec,
    /// 0x15
    Alert,
    /// 0x16
    Handshake,
    /// 0x17
    ApplicationData,
}

impl ContentType {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Invalid => [0x00],
            Self::ChangeCipherSpec => [0x14],
            Self::Alert => [0x15],
            Self::Handshake => [0x16],
            Self::ApplicationData => [0x17],
        }
    }
}

impl Deserializable for ContentType {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let content_type = match buf[0] {
            0x00 => Self::Invalid,
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert,
            0x16 => Self::Handshake,
            0x17 => Self::ApplicationData,
            _ => return Err(DeserializationError::InvalidEnumValue),
        };
        return Ok((content_type, Self::BYTES));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    Tls_1_2,
    Tls_1_3,
}

impl ProtocolVersion {
    pub const BYTES: usize = 2;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Tls_1_2 => [0x03, 0x03],
            Self::Tls_1_3 => [0x03, 0x04],
        }
    }
}

impl Deserializable for ProtocolVersion {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let protocol_version = match buf[..Self::BYTES] {
            [0x03, 0x03] => Self::Tls_1_2,
            [0x03, 0x04] => Self::Tls_1_3,
            _ => return Err(DeserializationError::InvalidEnumValue),
        };

        Ok((protocol_version, Self::BYTES))
    }
}

/// The record type is the top-level abstraction.
///
/// TODO: this is a literal translation of the specification. There could be some deviation (not
/// sure if any good though): use Vector<U16, U8>, use fragment: &[u8], use fragment: [u8; 1 << 14]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    content_type: ContentType,

    /// per RFC 8446: must be set to 0x0303 for all records generated by a TLS 1.3 implementation
    /// other than an initial ClientHello, where it may also be 0x0301 for compatibility purposes
    legacy_record_version: ProtocolVersion,

    /// the length of the fragment in bytes. Must not exceed 2^14 bytes; an endpoint receiving a
    /// record that exceeds thislength must terminate the connection with a "record_overflow" alert
    length: U16,

    fragment: Vec<u8>,
}

impl Deserializable for Record {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        written += self.content_type.serialize(buf)?;
        buf = buf
            .get_mut(ContentType::BYTES..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        written += self.legacy_record_version.serialize(buf)?;
        buf = buf
            .get_mut(ProtocolVersion::BYTES..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        written += self.length.serialize(buf)?;
        buf = buf
            .get_mut(U16::BYTES..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        written += buf.write(&self.fragment)?;

        Ok(written)
    }

    fn deserialize(mut buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        // Check the static fields first and parse them, then check the length of the fragment and
        // read the payload
        let static_length = ContentType::BYTES + ProtocolVersion::BYTES + U16::BYTES;
        if buf.len() < static_length {
            return Err(DeserializationError::insufficient_buffer_length(
                static_length,
                buf.len(),
            ));
        }

        let (content_type, content_size) = ContentType::deserialize(buf)?;
        buf = buf
            .get(content_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (legacy_record_version, version_size) = ProtocolVersion::deserialize(buf)?;
        buf = buf
            .get(version_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (length, length_size) = U16::deserialize(buf)?;
        buf = buf.get(length_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        let fragment_size: usize = length.into();
        if buf.len() < fragment_size {
            return Err(DeserializationError::insufficient_vec_data(
                fragment_size,
                buf.len(),
            ));
        }
        let mut fragment = vec![];
        fragment.extend_from_slice(
            buf.get(..fragment_size)
                .expect(UNEXPECTED_OUT_OF_BOUND_PANIC),
        );

        return Ok((
            Record {
                content_type,
                legacy_record_version,
                length,
                fragment,
            },
            content_size + version_size + length_size + fragment_size,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize a vector with some simple types, then deserialize
    #[test]
    fn vector_serde() {
        // empty vector
        let vector = Vector::<U8, U8> {
            size: U8(0),
            elems: vec![],
        };
        let mut buffer = [0u8; 1];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 1);
        assert_eq!(buffer, [0]);

        // non-empty vector
        let vector = Vector::<U8, U8> {
            size: U8(2),
            elems: vec![U8(255), U8(255)],
        };
        let mut buffer = [0u8; 3];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 3);
        assert_eq!(buffer, [2, 255, 255]);
    }

    #[test]
    fn content_type_serde() {
        let mut buf = [0u8];
        assert_eq!(ContentType::Invalid.serialize(&mut buf).unwrap(), 1);
        assert_eq!(buf, [0]);
        assert_eq!(
            ContentType::ChangeCipherSpec.serialize(&mut buf).unwrap(),
            1
        );
        assert_eq!(buf, [20]);
        assert_eq!(ContentType::Alert.serialize(&mut buf).unwrap(), 1);
        assert_eq!(buf, [21]);
        assert_eq!(ContentType::Handshake.serialize(&mut buf).unwrap(), 1);
        assert_eq!(buf, [22]);
        assert_eq!(ContentType::ApplicationData.serialize(&mut buf).unwrap(), 1);
        assert_eq!(buf, [23]);
        assert_eq!(
            ContentType::deserialize(&[]),
            Err(DeserializationError::insufficient_buffer_length(1, 0))
        );
        assert_eq!(
            ContentType::deserialize(&[1]),
            Err(DeserializationError::InvalidEnumValue)
        );
        assert_eq!(
            ContentType::deserialize(&[0]),
            Ok((ContentType::Invalid, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[20]),
            Ok((ContentType::ChangeCipherSpec, 1))
        );
        assert_eq!(ContentType::deserialize(&[21]), Ok((ContentType::Alert, 1)));
        assert_eq!(
            ContentType::deserialize(&[22]),
            Ok((ContentType::Handshake, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[23]),
            Ok((ContentType::ApplicationData, 1))
        );
    }

    #[test]
    fn protocol_version_serde() {
        let mut buf = [0u8; ProtocolVersion::BYTES];
        assert_eq!(ProtocolVersion::Tls_1_2.serialize(&mut buf).unwrap(), 2);
        assert_eq!(buf, [3, 3]);
        assert_eq!(ProtocolVersion::Tls_1_3.serialize(&mut buf).unwrap(), 2);
        assert_eq!(buf, [3, 4]);
        assert_eq!(
            ProtocolVersion::deserialize(&[0]),
            Err(DeserializationError::insufficient_buffer_length(2, 1))
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[0, 0]),
            Err(DeserializationError::InvalidEnumValue)
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[3, 3]),
            Ok((ProtocolVersion::Tls_1_2, 2))
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[3, 4]),
            Ok((ProtocolVersion::Tls_1_3, 2))
        );
    }

    #[test]
    fn record_serde() {
        let record = Record {
            content_type: ContentType::Handshake,
            legacy_record_version: ProtocolVersion::Tls_1_3,
            length: U16(5),
            fragment: [0u8; 5].to_vec(),
        };
        let expected_buf = [22, 3, 4, 0, 5, 0, 0, 0, 0, 0];
        let mut buf = [0u8; 10];
        record.serialize(&mut buf).unwrap();
        assert_eq!(buf, expected_buf);
        assert_eq!(Record::deserialize(&expected_buf), Ok((record, 10)));
    }
}
