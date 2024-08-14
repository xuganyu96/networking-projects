use crate::{
    traits::{Deserializable, DeserializationError},
    UNEXPECTED_OUT_OF_BOUND_PANIC,
};
use std::io::Write;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U8(pub u8);

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
pub struct U16(pub u16);

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

impl std::fmt::Display for U16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U24(pub u32);

impl U24 {
    pub const BYTES: usize = 3;
}

impl Deserializable for U24 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO: remove magic number
        buf.write(&self.0.to_be_bytes()[1..])
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector<T, U> {
    /// The number of bytes needed to serialize and deserialize the vector
    pub size: T,
    /// The individual elements
    pub elems: Vec<U>,
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

    fn deserialize(mut buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let mut written: usize = 0;
        let (datalen, datalen_size) = T::deserialize(buf)?;
        written += datalen_size;
        let datalen_usize: usize = datalen.into();

        if buf.len() < datalen_usize {
            return Err(DeserializationError::insufficient_vec_data(
                datalen_usize,
                buf.len(),
            ));
        }
        buf = buf
            .get(datalen_size..datalen_size + datalen_usize)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        let mut elems: Vec<U> = vec![];
        while buf.len() > 0 {
            let (elem, elem_size) = U::deserialize(buf)?;
            written += elem_size;
            elems.push(elem);
            buf = buf.get(elem_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
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

    /// A special test type that is not real but is useful for tesing
    /// 0xFF
    Opaque,
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
            Self::Opaque => [0xFF],
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
            0xFF => Self::Opaque,
            _ => return Err(DeserializationError::InvalidEnumValue),
        };
        return Ok((content_type, Self::BYTES));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    Tls_1_0,
    Tls_1_1,
    Tls_1_2,
    Tls_1_3,
}

impl ProtocolVersion {
    pub const BYTES: usize = 2;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Tls_1_0 => [0x03, 0x01],
            Self::Tls_1_1 => [0x03, 0x02],
            Self::Tls_1_2 => [0x03, 0x03],
            Self::Tls_1_3 => [0x03, 0x04],
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls_1_0 => write!(f, "<TLS 1.0>"),
            Self::Tls_1_1 => write!(f, "<TLS 1.1>"),
            Self::Tls_1_2 => write!(f, "<TLS 1.2>"),
            Self::Tls_1_3 => write!(f, "<TLS 1.3>"),
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
            [0x03, 0x01] => Self::Tls_1_0,
            [0x03, 0x02] => Self::Tls_1_1,
            [0x03, 0x03] => Self::Tls_1_2,
            [0x03, 0x04] => Self::Tls_1_3,
            _ => return Err(DeserializationError::InvalidEnumValue),
        };

        Ok((protocol_version, Self::BYTES))
    }
}

/// TLS 1.3 no longer supports plaintext compressions due to the side-channel vulnerabilities;
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CompressionMethod {}

impl Deserializable for CompressionMethod {
    fn serialize(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        return std::io::Result::Ok(0);
    }

    fn deserialize(_buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        panic!("TLS 1.3 does not support compression methods anymore!");
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CipherSuite {
    UNKNOWN([u8; Self::BYTES]),
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,
    TLS_AES_128_CCM_8_SHA256,
}

impl CipherSuite {
    pub const BYTES: usize = 2;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::UNKNOWN(encoding) => encoding.clone(),
            Self::TLS_AES_128_GCM_SHA256 => [0x13, 0x01],
            Self::TLS_AES_256_GCM_SHA384 => [0x13, 0x02],
            Self::TLS_CHACHA20_POLY1305_SHA256 => [0x13, 0x03],
            Self::TLS_AES_128_CCM_SHA256 => [0x13, 0x04],
            Self::TLS_AES_128_CCM_8_SHA256 => [0x13, 0x05],
        }
    }
}

impl Deserializable for CipherSuite {
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
        let encoding = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let cipher_suite = match *encoding {
            [0x13, 0x01] => Self::TLS_AES_128_GCM_SHA256,
            [0x13, 0x02] => Self::TLS_AES_256_GCM_SHA384,
            [0x13, 0x03] => Self::TLS_CHACHA20_POLY1305_SHA256,
            [0x13, 0x04] => Self::TLS_AES_128_CCM_SHA256,
            [0x13, 0x05] => Self::TLS_AES_128_CCM_8_SHA256,
            _ => Self::UNKNOWN([encoding[0], encoding[1]]),
        };

        Ok((cipher_suite, Self::BYTES))
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SignatureScheme {
    Private([u8; Self::BYTES]),
    ecdsa_secp256r1_sha256, // 0x0403
    ecdsa_secp384r1_sha384, // 0x0503
    ecdsa_secp521r1_sha512, // 0x0603
    ed25519,                // 0x0807
    rsa_pss_rsae_sha256,    // 0x0804
    rsa_pss_rsae_sha384,    // 0x0805
    rsa_pss_rsae_sha512,    // 0x0806
    rsa_pkcs1_sha256,       // 0x0401
    rsa_pkcs1_sha384,       // 0x0501
    rsa_pkcs1_sha512,       // 0x0601
}

impl SignatureScheme {
    pub const BYTES: usize = 2;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::ecdsa_secp256r1_sha256 => [0x04, 0x03],
            Self::ecdsa_secp384r1_sha384 => [0x05, 0x03],
            Self::ecdsa_secp521r1_sha512 => [0x06, 0x03],
            Self::ed25519 => [0x08, 0x07],
            Self::rsa_pss_rsae_sha256 => [0x08, 0x04],
            Self::rsa_pss_rsae_sha384 => [0x08, 0x05],
            Self::rsa_pss_rsae_sha512 => [0x08, 0x06],
            Self::rsa_pkcs1_sha256 => [0x04, 0x01],
            Self::rsa_pkcs1_sha384 => [0x05, 0x01],
            Self::rsa_pkcs1_sha512 => [0x06, 0x01],
            Self::Private(encoding) => *encoding,
        }
    }
}

impl Deserializable for SignatureScheme {
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let encoding = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let scheme = match *encoding {
            [0x04, 0x03] => Self::ecdsa_secp256r1_sha256,
            [0x05, 0x03] => Self::ecdsa_secp384r1_sha384,
            [0x06, 0x03] => Self::ecdsa_secp521r1_sha512,
            [0x08, 0x07] => Self::ed25519,
            [0x08, 0x04] => Self::rsa_pss_rsae_sha256,
            [0x08, 0x05] => Self::rsa_pss_rsae_sha384,
            [0x08, 0x06] => Self::rsa_pss_rsae_sha512,
            [0x04, 0x01] => Self::rsa_pkcs1_sha256,
            [0x05, 0x01] => Self::rsa_pkcs1_sha384,
            [0x06, 0x01] => Self::rsa_pkcs1_sha512,
            _ => {
                let mut dst = [0u8; Self::BYTES];
                dst.copy_from_slice(encoding);
                Self::Private(dst)
            }
        };

        Ok((scheme, Self::BYTES))
    }

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
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
}
