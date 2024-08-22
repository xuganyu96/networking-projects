use crate::{
    traits::{Deserializable, DeserializableNum, DeserializationError, Zero},
    UNEXPECTED_OUT_OF_BOUND_PANIC,
};
use std::ops::Add;
use std::{io::Write, num::TryFromIntError};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U8(pub u8);

impl U8 {
    pub const BYTES: usize = 1;
}

impl Deserializable for U8 {
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        return Ok((Self(buf[0]), Self::BYTES));
    }

    fn size(&self) -> usize {
        Self::BYTES
    }
}

impl From<U8> for usize {
    fn from(value: U8) -> Self {
        value.0.into()
    }
}

impl Zero for U8 {
    fn zero() -> Self {
        Self(0)
    }
}

impl Add for U8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl TryFrom<usize> for U8 {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let truncate = value.try_into()?;
        Ok(Self(truncate))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U16(pub u16);

impl U16 {
    pub const BYTES: usize = 2;
}

impl Deserializable for U16 {
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
    }
}

impl From<U16> for usize {
    fn from(value: U16) -> Self {
        value.0.into()
    }
}

impl Zero for U16 {
    fn zero() -> Self {
        Self(0)
    }
}

impl Add for U16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl TryFrom<usize> for U16 {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let truncate = value.try_into()?;
        Ok(Self(truncate))
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
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO: remove magic number
        buf.write(&self.0.to_be_bytes()[1..])
    }

    /// Only read the first three bytes from the input buffer and parses them into a u32
    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
    }
}

impl Into<usize> for U24 {
    fn into(self) -> usize {
        self.0.try_into().expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
    }
}

impl Zero for U24 {
    fn zero() -> Self {
        Self(0)
    }
}

impl Add for U24 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl TryFrom<usize> for U24 {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let truncate = value.try_into()?;
        Ok(Self(truncate))
    }
}

/// T is the length type; U is the element type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector<T, U> {
    /// The number of bytes needed to serialize and deserialize the vector
    pub elems_size: T,
    /// The individual elements
    pub elems: Vec<U>,
}

impl<T, U> Vector<T, U>
where
    T: DeserializableNum<Output = T>,
    U: Deserializable,
    // Unwrapping a result requires the Error type to implement Debug
    <T as TryFrom<usize>>::Error: std::fmt::Debug,
{
    /// Return a slice of the elements
    pub fn as_slice(&self) -> &[U] {
        &self.elems
    }

    /// Create an empty vector
    pub fn empty() -> Self {
        Self {
            elems_size: T::zero(),
            elems: vec![],
        }
    }

    /// Push an element to the end of the data slice
    pub fn push(&mut self, elem: U) {
        let elem_usize = elem.size();
        self.elems.push(elem);

        // need to update self.elems_size, as well
        let elem_size: T = <T as TryFrom<usize>>::try_from(elem_usize).unwrap();
        self.elems_size = self.elems_size + elem_size;
    }
}

impl<T> Vector<T, U8>
where
    T: DeserializableNum<Output = T>,
    <T as TryFrom<usize>>::Error: std::fmt::Debug,
{
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let data = bytes.iter().map(|byte| U8(*byte)).collect::<Vec<U8>>();
        Self {
            elems_size: <T as TryFrom<usize>>::try_from(bytes.len()).expect("input bytes too long"),
            elems: data,
        }
    }
}

impl<T, U> Deserializable for Vector<T, U>
where
    T: DeserializableNum<Output = T>,
    U: Deserializable,
    <T as TryFrom<usize>>::Error: std::fmt::Debug,
{
    type Context = (T::Context, U::Context);
    /// First serialize the size, then serialize the data
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        // TODO: need to check that buf actually has enough lenth left
        written += self.elems_size.serialize(&mut buf[written..])?;
        for elem in self.as_slice() {
            written += elem.serialize(&mut buf[written..])?;
        }
        return Ok(written);
    }

    fn deserialize(
        mut buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (t_context, u_context) = context;
        let mut written: usize = 0;
        let (datalen, datalen_size) = T::deserialize(buf, t_context)?;
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
            let (elem, elem_size) = U::deserialize(buf, u_context)?;
            written += elem_size;
            elems.push(elem);
            buf = buf.get(elem_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        }

        let vector = Self {
            elems_size: datalen,
            elems,
        };

        Ok((vector, written))
    }

    fn size(&self) -> usize {
        self.elems_size.size() + self.elems.iter().map(|elem| elem.size()).sum::<usize>()
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
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
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
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
    }
}

/// TLS 1.3 no longer supports plaintext compressions due to the side-channel vulnerabilities;
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CompressionMethod {
    Null,
}

impl CompressionMethod {
    pub const BYTES: usize = 1;
}

impl Deserializable for CompressionMethod {
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&[0u8])
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }

        Ok((Self::Null, Self::BYTES))
    }
    fn size(&self) -> usize {
        Self::BYTES
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
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
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
    type Context = ();
    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    fn size(&self) -> usize {
        Self::BYTES
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// 0x0017
    secp256r1,
    /// 0x0018
    secp384r1,
    /// 0x0019
    secp521r1,
    /// 0x001D
    x25519,
    /// 0x001E
    x448,
    /// 0x0100
    ffdhe2048,
    /// 0x0101
    ffdhe3072,
    /// 0x0102
    ffdhe4096,
    /// 0x0103
    ffdhe6144,
    /// 0x0104
    ffdhe8192,
    /// for private use
    Private([u8; Self::BYTES]),
}

impl NamedGroup {
    pub const BYTES: usize = 2;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::secp256r1 => [0x00, 0x17],
            Self::secp384r1 => [0x00, 0x18],
            Self::secp521r1 => [0x00, 0x19],
            Self::x25519 => [0x00, 0x1D],
            Self::x448 => [0x00, 0x1E],
            Self::ffdhe2048 => [0x01, 0x00],
            Self::ffdhe3072 => [0x01, 0x01],
            Self::ffdhe4096 => [0x01, 0x02],
            Self::ffdhe6144 => [0x01, 0x03],
            Self::ffdhe8192 => [0x01, 0x04],
            Self::Private(encoding) => *encoding,
        }
    }
}

impl Deserializable for NamedGroup {
    type Context = ();
    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }

        let encoding = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let named_group = match *encoding {
            [0x00, 0x17] => Self::secp256r1,
            [0x00, 0x18] => Self::secp384r1,
            [0x00, 0x19] => Self::secp521r1,
            [0x00, 0x1D] => Self::x25519,
            [0x00, 0x1E] => Self::x448,
            [0x01, 0x00] => Self::ffdhe2048,
            [0x01, 0x01] => Self::ffdhe3072,
            [0x01, 0x02] => Self::ffdhe4096,
            [0x01, 0x03] => Self::ffdhe6144,
            [0x01, 0x04] => Self::ffdhe8192,
            _ => {
                let mut _named_group = [0u8; Self::BYTES];
                _named_group.copy_from_slice(encoding);
                Self::Private(_named_group)
            }
        };

        Ok((named_group, Self::BYTES))
    }

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }
    fn size(&self) -> usize {
        Self::BYTES
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskKeyExchangeMode {
    /// 0x00
    psk_ke,
    /// 0x01
    psk_dhe_ke,
}

impl PskKeyExchangeMode {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::psk_ke => [0],
            Self::psk_dhe_ke => [1],
        }
    }
}

impl Deserializable for PskKeyExchangeMode {
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }

        let encoding = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let mode = match *encoding {
            [0] => Self::psk_ke,
            [1] => Self::psk_dhe_ke,
            _ => {
                return Err(DeserializationError::InvalidEnumValue);
            }
        };

        Ok((mode, Self::BYTES))
    }
    fn size(&self) -> usize {
        Self::BYTES
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
            elems_size: U8(0),
            elems: vec![],
        };
        let mut buffer = [0u8; 1];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 1);
        assert_eq!(buffer, [0]);

        // non-empty vector
        let vector = Vector::<U8, U8> {
            elems_size: U8(2),
            elems: vec![U8(255), U8(255)],
        };
        let mut buffer = [0u8; 3];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 3);
        assert_eq!(buffer, [2, 255, 255]);
    }

    #[test]
    fn vector_empty_then_push() {
        let mut versions = Vector::<U8, ProtocolVersion>::empty();
        assert_eq!(versions.size(), 1);
        assert_eq!(versions.elems_size, U8(0));
        assert_eq!(versions.elems.len(), 0);

        versions.push(ProtocolVersion::Tls_1_3);
        versions.push(ProtocolVersion::Tls_1_2);
        assert_eq!(versions.size(), 5);
        assert_eq!(versions.elems_size, U8(4));
        assert_eq!(
            versions.as_slice(),
            &[ProtocolVersion::Tls_1_3, ProtocolVersion::Tls_1_2]
        );
    }

    #[test]
    fn vector_from_byte_slice() {
        let vector: Vector<U16, U8> = Vector::from_slice(&[69; 420]);
        assert_eq!(vector.size(), 422);
        assert_eq!(vector.elems_size, U16(420));
        assert_eq!(vector.as_slice(), &[U8(69); 420]);
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
            ContentType::deserialize(&[], ()),
            Err(DeserializationError::insufficient_buffer_length(1, 0))
        );
        assert_eq!(
            ContentType::deserialize(&[1], ()),
            Err(DeserializationError::InvalidEnumValue)
        );
        assert_eq!(
            ContentType::deserialize(&[0], ()),
            Ok((ContentType::Invalid, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[20], ()),
            Ok((ContentType::ChangeCipherSpec, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[21], ()),
            Ok((ContentType::Alert, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[22], ()),
            Ok((ContentType::Handshake, 1))
        );
        assert_eq!(
            ContentType::deserialize(&[23], ()),
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
            ProtocolVersion::deserialize(&[0], ()),
            Err(DeserializationError::insufficient_buffer_length(2, 1))
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[0, 0], ()),
            Err(DeserializationError::InvalidEnumValue)
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[3, 3], ()),
            Ok((ProtocolVersion::Tls_1_2, 2))
        );
        assert_eq!(
            ProtocolVersion::deserialize(&[3, 4], ()),
            Ok((ProtocolVersion::Tls_1_3, 2))
        );
    }
}
