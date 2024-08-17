//! Handshake Extensions
use crate::primitives::{NamedGroup, PskKeyExchangeMode, SignatureScheme, Vector, U16, U8};
use crate::traits::{Deserializable, DeserializationError};
use crate::UNEXPECTED_OUT_OF_BOUND_PANIC;
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionType {
    /// Both for testing and for accommodating unsupported extension types
    Opaque([u8; Self::BYTES]),

    /// Which signature algorithms may be used in digital signatures; applies to the signature in
    /// `CertificateVerify`
    SignatureAlgorithms,

    SupportedGroups,

    /// 0x2D
    PskKeyExchangeModes,
}

impl ExtensionType {
    pub const BYTES: usize = 2;
    pub const TESTING: Self = Self::Opaque([0xFF, 0xFF]);

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Opaque(encoding) => encoding.clone(),
            Self::SignatureAlgorithms => [0, 13],
            Self::SupportedGroups => [0, 0x0A],
            Self::PskKeyExchangeModes => [0, 45],
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
            [0, 13] => Self::SignatureAlgorithms,
            [0, 0x0A] => Self::SupportedGroups,
            [0, 45] => Self::PskKeyExchangeModes,
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
    SignatureAlgorithms(SignatureSchemeList),
    SupportedGroups(SupportedGroups),
    PskKeyExchangeModes(PskKeyExchangeModes),
}

impl Deserializable for ExtensionPayload {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
            Self::SignatureAlgorithms(sigalgs) => sigalgs.serialize(&mut buf),
            Self::SupportedGroups(groups) => groups.serialize(&mut buf),
            Self::PskKeyExchangeModes(modes) => modes.serialize(&mut buf),
        }
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let fragment = buf.to_vec();
        Ok((Self::Opaque(fragment), buf.len()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub length: U16,
    pub payload: ExtensionPayload,
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
            ExtensionType::SignatureAlgorithms => {
                let (sigalgs, _) = SignatureSchemeList::deserialize(&data_slice)?;
                ExtensionPayload::SignatureAlgorithms(sigalgs)
            }
            ExtensionType::SupportedGroups => {
                let (named_groups, _) = SupportedGroups::deserialize(&data_slice)?;
                ExtensionPayload::SupportedGroups(named_groups)
            }
            ExtensionType::PskKeyExchangeModes => {
                let (psk_key_exchange_modes, _) = PskKeyExchangeModes::deserialize(&data_slice)?;
                ExtensionPayload::PskKeyExchangeModes(psk_key_exchange_modes)
            }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureSchemeList {
    pub supported_signature_algorithms: Vector<U16, SignatureScheme>,
}

impl Deserializable for SignatureSchemeList {
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.supported_signature_algorithms.serialize(buf)
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (supported_signature_algorithms, size) =
            Vector::<U16, SignatureScheme>::deserialize(buf)?;

        Ok((
            Self {
                supported_signature_algorithms,
            },
            size,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedGroups {
    pub named_group_list: Vector<U16, NamedGroup>,
}

impl Deserializable for SupportedGroups {
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.named_group_list.serialize(buf)
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (named_group_list, size) = Vector::deserialize(buf)?;

        Ok((Self { named_group_list }, size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vector<U8, PskKeyExchangeMode>,
}

impl Deserializable for PskKeyExchangeModes {
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.ke_modes.serialize(buf)
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (ke_modes, size) = Vector::deserialize(buf)?;

        Ok((Self { ke_modes }, size))
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

    #[test]
    fn signature_algorithms_serde() {
        let expected_buf = [0, 13, 0, 10, 0, 8, 4, 1, 5, 1, 6, 1, 0xFF, 0xFF];
        let expected_signature_algorithms = SignatureSchemeList {
            supported_signature_algorithms: Vector::<U16, SignatureScheme> {
                size: U16(8),
                elems: vec![
                    SignatureScheme::rsa_pkcs1_sha256,
                    SignatureScheme::rsa_pkcs1_sha384,
                    SignatureScheme::rsa_pkcs1_sha512,
                    SignatureScheme::Private([0xFF, 0xFF]),
                ],
            },
        };
        let expected_extension = Extension {
            extension_type: ExtensionType::SignatureAlgorithms,
            length: U16(10),
            payload: ExtensionPayload::SignatureAlgorithms(expected_signature_algorithms),
        };
        let mut buf = [0u8; 16];
        let written = expected_extension.serialize(&mut buf).unwrap();

        assert_eq!(
            buf.get(..written).expect(UNEXPECTED_OUT_OF_BOUND_PANIC),
            &expected_buf
        );
        assert_eq!(
            Extension::deserialize(&expected_buf),
            Ok((expected_extension, written)),
        );
    }
}
