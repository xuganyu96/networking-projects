//! Handshake Extensions
use crate::handshake::HandshakeType;
use crate::primitives::{
    NamedGroup, ProtocolVersion, PskKeyExchangeMode, SignatureScheme, Vector, U16, U8,
};
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

    /// 0x0033
    KeyShare,

    SupportedVersions,

    // TODO: I don't understand what status_request is about
    // StatusRequest,
    ServerName,
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
            Self::KeyShare => [0x00, 0x33],
            Self::SupportedVersions => [0, 43],
            // Self::StatusRequest => [0, 5],
            Self::ServerName => [0, 0],
        }
    }
}

impl Deserializable for ExtensionType {
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
        let extension_type = match *encoding {
            [0, 13] => Self::SignatureAlgorithms,
            [0, 0x0A] => Self::SupportedGroups,
            [0, 45] => Self::PskKeyExchangeModes,
            [0, 51] => Self::KeyShare,
            [0, 43] => Self::SupportedVersions,
            [0, 0] => Self::ServerName,
            // [0, 5] => Self::StatusRequest,
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
    KeyShare(KeyShare),
    SupportedVersions(SupportedVersions),
    ServerName(Vector<U16, ServerName>),
    // StatusRequest(StatusRequest),
}

impl Deserializable for ExtensionPayload {
    type Context = ();
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
            Self::SignatureAlgorithms(sigalgs) => sigalgs.serialize(&mut buf),
            Self::SupportedGroups(groups) => groups.serialize(&mut buf),
            Self::PskKeyExchangeModes(modes) => modes.serialize(&mut buf),
            Self::KeyShare(key_share) => key_share.serialize(&mut buf),
            Self::SupportedVersions(supported_versions) => supported_versions.serialize(&mut buf),
            Self::ServerName(server_name) => server_name.serialize(&mut buf),
            // Self::StatusRequest(status_request) => status_request.serialize(&mut buf),
        }
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
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
    type Context = HandshakeType;
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

    fn deserialize(
        mut buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let static_size = ExtensionType::BYTES + U16::BYTES;
        if buf.len() < static_size {
            return Err(DeserializationError::insufficient_buffer_length(
                static_size,
                buf.len(),
            ));
        }
        let (extension_type, type_size) = ExtensionType::deserialize(buf, ())?;
        buf = buf.get(type_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (length, length_size) = U16::deserialize(buf, ())?;
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
                let (sigalgs, _) = SignatureSchemeList::deserialize(&data_slice, ())?;
                ExtensionPayload::SignatureAlgorithms(sigalgs)
            }
            ExtensionType::SupportedGroups => {
                let (named_groups, _) = SupportedGroups::deserialize(&data_slice, ())?;
                ExtensionPayload::SupportedGroups(named_groups)
            }
            ExtensionType::PskKeyExchangeModes => {
                let (psk_key_exchange_modes, _) =
                    PskKeyExchangeModes::deserialize(&data_slice, ())?;
                ExtensionPayload::PskKeyExchangeModes(psk_key_exchange_modes)
            }
            ExtensionType::KeyShare => {
                let (key_share, _) = KeyShare::deserialize(&data_slice, context)?;
                ExtensionPayload::KeyShare(key_share)
            }
            ExtensionType::SupportedVersions => {
                let (supported_versions, _) = SupportedVersions::deserialize(&data_slice, context)?;
                ExtensionPayload::SupportedVersions(supported_versions)
            }
            ExtensionType::ServerName => {
                let (server_name_list, _) = Vector::deserialize(&data_slice, ((), ()))?;
                ExtensionPayload::ServerName(server_name_list)
            }
            // ExtensionType::StatusRequest => {
            //     let (status_request, _) = StatusRequest::deserialize(&data_slice, ())?;
            //     ExtensionPayload::StatusRequest(status_request)
            // }
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
    type Context = ();
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.supported_signature_algorithms.serialize(buf)
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (supported_signature_algorithms, size) =
            Vector::<U16, SignatureScheme>::deserialize(buf, ((), ()))?;

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
    type Context = ();
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.named_group_list.serialize(buf)
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (named_group_list, size) = Vector::deserialize(buf, ((), ()))?;

        Ok((Self { named_group_list }, size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vector<U8, PskKeyExchangeMode>,
}

impl Deserializable for PskKeyExchangeModes {
    type Context = ();
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.ke_modes.serialize(buf)
    }

    fn deserialize(
        buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (ke_modes, size) = Vector::deserialize(buf, ((), ()))?;

        Ok((Self { ke_modes }, size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyShare {
    ClientKeyShare(ClientKeyShare),
    ServerKeyShare(ServerKeyShare),
    // TODO: we are omitting the payload in HelloRetryRequest
}

impl Deserializable for KeyShare {
    type Context = HandshakeType;

    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::ClientKeyShare(client_key_share) => client_key_share.serialize(buf),
            Self::ServerKeyShare(server_key_share) => server_key_share.serialize(buf),
        }
    }

    fn deserialize(
        buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (key_share, key_share_size) = match context {
            HandshakeType::ClientHello => {
                let (client_key_share, client_key_share_size) =
                    ClientKeyShare::deserialize(buf, ())?;
                let key_share = Self::ClientKeyShare(client_key_share);
                (key_share, client_key_share_size)
            }
            HandshakeType::ServerHello => {
                let (server_key_share, server_key_share_size) =
                    ServerKeyShare::deserialize(buf, ())?;
                let key_share = Self::ServerKeyShare(server_key_share);
                (key_share, server_key_share_size)
            }
            _ => panic!("invalid context"),
        };

        Ok((key_share, key_share_size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub named_group: NamedGroup,
    pub length: U16,
    pub key_exchange: Vec<u8>,
}

impl Deserializable for KeyShareEntry {
    type Context = ();

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let named_group_size = self.named_group.serialize(buf)?;
        buf = buf
            .get_mut(named_group_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let length_size = self.length.serialize(buf)?;
        buf = buf
            .get_mut(length_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let key_exchange_size = buf.write(&self.key_exchange)?;
        return Ok(named_group_size + length_size + key_exchange_size);
    }

    fn deserialize(
        mut buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let static_size = NamedGroup::BYTES + U16::BYTES;
        if buf.len() < static_size {
            return Err(DeserializationError::insufficient_buffer_length(
                static_size,
                buf.len(),
            ));
        }

        let (named_group, named_group_size) = NamedGroup::deserialize(buf, context)?;
        buf = buf
            .get(named_group_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (length, _) = U16::deserialize(buf, context)?;
        buf = buf.get(U16::BYTES..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let key_exchange_size: usize = length.into();
        if buf.len() < key_exchange_size {
            return Err(DeserializationError::insufficient_vec_data(
                key_exchange_size,
                buf.len(),
            ));
        }
        let key_exchange = buf
            .get(..key_exchange_size)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
            .to_vec();

        let entry = KeyShareEntry {
            named_group,
            length,
            key_exchange,
        };

        Ok((entry, static_size + key_exchange_size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyShare {
    pub client_shares: Vector<U16, KeyShareEntry>,
}

impl Deserializable for ClientKeyShare {
    type Context = ();

    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.client_shares.serialize(buf)
    }

    fn deserialize(
        buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (client_shares, client_share_size) = Vector::deserialize(buf, ((), context))?;
        let client_key_share = Self { client_shares };
        Ok((client_key_share, client_share_size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedVersions {
    ClientSupportedVersions(Vector<U8, ProtocolVersion>),
    ServerSupportedVersion(ProtocolVersion),
}

impl Deserializable for SupportedVersions {
    type Context = HandshakeType;

    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::ClientSupportedVersions(versions) => versions.serialize(buf),
            Self::ServerSupportedVersion(version) => version.serialize(buf),
        }
    }

    fn deserialize(
        buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (supported_versions, size) = match context {
            HandshakeType::ClientHello => {
                let (versions, versions_size) = Vector::deserialize(buf, ((), ()))?;
                (Self::ClientSupportedVersions(versions), versions_size)
            }
            HandshakeType::ServerHello => {
                let (version, version_size) = ProtocolVersion::deserialize(buf, ())?;
                (Self::ServerSupportedVersion(version), version_size)
            }
            _ => panic!("invalid context"),
        };

        Ok((supported_versions, size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyShare {
    server_share: KeyShareEntry,
}

impl Deserializable for ServerKeyShare {
    type Context = ();

    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.server_share.serialize(buf)
    }

    fn deserialize(
        buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let (server_share, server_share_size) = KeyShareEntry::deserialize(buf, context)?;
        let server_key_share = Self { server_share };

        Ok((server_key_share, server_share_size))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameType {
    Hostname,
}

impl NameType {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Hostname => [0],
        }
    }
}

impl Deserializable for NameType {
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
        let name_type = match *encoding {
            [0] => Self::Hostname,
            _ => {
                return Err(DeserializationError::InvalidEnumValue);
            }
        };

        Ok((name_type, Self::BYTES))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerName {
    pub name_type: NameType,
    pub name_length: U16,
    /// currently only supports DNS hostnames, which must be ASCII codes, thus can be assumed to be
    /// valid UTF-8 strings
    pub name: String,
}

impl Deserializable for ServerName {
    type Context = ();

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let name_type_size = self.name_type.serialize(&mut buf)?;
        buf = buf
            .get_mut(name_type_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let name_length_size = self.name_length.serialize(&mut buf)?;
        buf = buf
            .get_mut(name_length_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let name_size = buf.write(&self.name.as_bytes())?;

        Ok(name_type_size + name_length_size + name_size)
    }
    fn deserialize(
        mut buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        let static_size = NameType::BYTES + U16::BYTES;
        if buf.len() < static_size {
            return Err(DeserializationError::insufficient_buffer_length(
                static_size,
                buf.len(),
            ));
        }
        let (name_type, name_type_size) = NameType::deserialize(buf, ())?;
        buf = buf
            .get(name_type_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (name_length, name_length_size) = U16::deserialize(buf, ())?;
        buf = buf
            .get(name_length_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        let name_length_usize: usize = name_length.into();
        if buf.len() < name_length_usize {
            return Err(DeserializationError::insufficient_vec_data(
                name_length_usize,
                buf.len(),
            ));
        }
        let name = String::from_utf8(
            buf.get(..name_length_usize)
                .expect(UNEXPECTED_OUT_OF_BOUND_PANIC)
                .to_vec(),
        )
        .unwrap();

        let server_name = ServerName {
            name_type,
            name_length,
            name,
        };

        Ok((
            server_name,
            name_type_size + name_length_size + name_length_usize,
        ))
    }
}

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct StatusRequest {}
//
// impl Deserializable for StatusRequest {
//     type Context = ();
//
//     fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
//         todo!();
//     }
//
//     fn deserialize(
//         buf: &[u8],
//         context: Self::Context,
//     ) -> Result<(Self, usize), DeserializationError> {
//         todo!();
//     }
// }

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
            Extension::deserialize(&expected_buf, HandshakeType::ClientHello),
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
            Extension::deserialize(&expected_buf, HandshakeType::ClientHello),
            Ok((expected_extension, written)),
        );
    }

    #[test]
    fn key_share_entry_serde() {
        let expected_buf = [0xff, 0xff, 0x00, 0x05, 1, 2, 3, 4, 5];
        let expected_entry = KeyShareEntry {
            named_group: NamedGroup::Private([0xff, 0xff]),
            length: U16(5),
            key_exchange: vec![1, 2, 3, 4, 5],
        };

        let mut buf = [0u8; 64];
        let written = expected_entry.serialize(&mut buf).unwrap();
        assert_eq!(buf.get(..written).unwrap(), &expected_buf);
        assert_eq!(
            KeyShareEntry::deserialize(&expected_buf, ()),
            Ok((expected_entry, written))
        );
    }

    #[test]
    fn supported_versions_serde() {
        let expected_encoding = [4, 3, 3, 3, 4];
        let expected_payload = SupportedVersions::ClientSupportedVersions(Vector {
            size: U8(4),
            elems: vec![ProtocolVersion::Tls_1_2, ProtocolVersion::Tls_1_3],
        });
        let mut buf = [0u8; 8];
        let written = expected_payload.serialize(&mut buf).unwrap();

        assert_eq!(buf.get(..written).unwrap(), expected_encoding);
        assert_eq!(
            SupportedVersions::deserialize(&expected_encoding, HandshakeType::ClientHello),
            Ok((expected_payload, written))
        );
    }
}
