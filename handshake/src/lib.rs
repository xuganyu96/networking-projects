pub mod extensions;
pub mod handshake;
pub mod primitives;
pub mod record;
pub mod traits;

pub const UNEXPECTED_OUT_OF_BOUND_PANIC: &str = "Unexpected out-of-bound error after length check";
pub const MAX_RECORD_LENGTH: usize = 1 << 14;

#[cfg(test)]
mod tests {
    use extensions::{
        ClientKeyShare, ExtensionPayload, ExtensionType, KeyShare, KeyShareEntry, NameType,
        PskKeyExchangeModes, ServerName, SignatureSchemeList, SupportedGroups, SupportedVersions,
    };
    use primitives::{NamedGroup, PskKeyExchangeMode, SignatureScheme};

    use super::*;
    use crate::extensions::Extension;
    use crate::handshake::{ClientHello, HandshakeMsg, HandshakeType};
    use crate::primitives::{
        CipherSuite, CompressionMethod, ContentType, ProtocolVersion, Vector, U16, U24, U8,
    };
    use crate::record::OpaqueRecord;
    use crate::traits::Deserializable;

    #[test]
    fn captured_client_hello_serde() {
        let encoding = [
            0x16, 0x03, 0x01, 0x00, 0xEE, 0x01, 0x00, 0x00, 0xEA, 0x03, 0x03, 0x30, 0x3E, 0xB7,
            0xF6, 0x6F, 0xAC, 0x63, 0x01, 0xFE, 0x65, 0x33, 0xB1, 0xB6, 0xCC, 0xBC, 0x63, 0x63,
            0x67, 0x46, 0x17, 0x6B, 0xEC, 0x1A, 0x47, 0x2B, 0xB3, 0x8C, 0xBE, 0xFC, 0x84, 0xAD,
            0x11, 0x20, 0x3E, 0x80, 0xEA, 0xAB, 0x85, 0x9A, 0xD5, 0x3C, 0x6B, 0xFA, 0x3A, 0xB3,
            0x41, 0x41, 0x67, 0x41, 0xF1, 0x0C, 0x5F, 0x5F, 0xCE, 0x12, 0x67, 0x05, 0xD5, 0xF3,
            0xB4, 0x91, 0xC3, 0xED, 0x73, 0x06, 0x00, 0x14, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03,
            0xC0, 0x2C, 0xC0, 0x2B, 0xCC, 0xA9, 0xC0, 0x30, 0xC0, 0x2F, 0xCC, 0xA8, 0x00, 0xFF,
            0x01, 0x00, 0x00, 0x8D, 0x00, 0x0D, 0x00, 0x16, 0x00, 0x14, 0x06, 0x03, 0x05, 0x03,
            0x04, 0x03, 0x08, 0x07, 0x08, 0x06, 0x08, 0x05, 0x08, 0x04, 0x06, 0x01, 0x05, 0x01,
            0x04, 0x01, 0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00,
            0x1D, 0x00, 0x17, 0x00, 0x18, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
            0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20, 0xC9, 0x95, 0x87, 0x67, 0xE3, 0x8D, 0x0D,
            0x6E, 0xF9, 0x5A, 0x71, 0x97, 0xAE, 0xF7, 0x95, 0x23, 0x6A, 0x0E, 0xB3, 0x4B, 0x30,
            0x43, 0x9B, 0x93, 0xBF, 0xAF, 0x25, 0xAB, 0x75, 0xEF, 0x40, 0x10, 0x00, 0x23, 0x00,
            0x00, 0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x00, 0x00, 0x13,
            0x00, 0x11, 0x00, 0x00, 0x0E, 0x61, 0x70, 0x69, 0x2E, 0x67, 0x69, 0x74, 0x68, 0x75,
            0x62, 0x2E, 0x63, 0x6F, 0x6D,
        ];
        let signature_algorithms = Extension {
            extension_type: ExtensionType::SignatureAlgorithms,
            length: U16(22),
            payload: ExtensionPayload::SignatureAlgorithms(SignatureSchemeList {
                supported_signature_algorithms: Vector {
                    size: U16(20),
                    elems: vec![
                        SignatureScheme::ecdsa_secp521r1_sha512,
                        SignatureScheme::ecdsa_secp384r1_sha384,
                        SignatureScheme::ecdsa_secp256r1_sha256,
                        SignatureScheme::ed25519,
                        SignatureScheme::rsa_pss_rsae_sha512,
                        SignatureScheme::rsa_pss_rsae_sha384,
                        SignatureScheme::rsa_pss_rsae_sha256,
                        SignatureScheme::rsa_pkcs1_sha512,
                        SignatureScheme::rsa_pkcs1_sha384,
                        SignatureScheme::rsa_pkcs1_sha256,
                    ],
                },
            }),
        };
        // TODO: status_request is defined in RFC 6066
        let status_request = Extension {
            extension_type: ExtensionType::Opaque([0x00, 0x05]),
            length: U16(5),
            payload: ExtensionPayload::Opaque(vec![1, 0, 0, 0, 0]),
        };
        let supported_groups = Extension {
            extension_type: ExtensionType::SupportedGroups,
            length: U16(8),
            payload: ExtensionPayload::SupportedGroups(SupportedGroups {
                named_group_list: Vector {
                    size: U16(6),
                    elems: vec![
                        NamedGroup::x25519,
                        NamedGroup::secp256r1,
                        NamedGroup::secp384r1,
                    ],
                },
            }),
        };
        let psk_key_exchange_modes = Extension {
            extension_type: ExtensionType::PskKeyExchangeModes,
            length: U16(2),
            payload: ExtensionPayload::PskKeyExchangeModes(PskKeyExchangeModes {
                ke_modes: Vector {
                    size: U8(1),
                    elems: vec![PskKeyExchangeMode::psk_dhe_ke],
                },
            }),
        };
        let key_share = Extension {
            extension_type: ExtensionType::KeyShare,
            length: U16(38),
            payload: ExtensionPayload::KeyShare(KeyShare::ClientKeyShare(ClientKeyShare {
                client_shares: Vector {
                    size: U16(36),
                    elems: vec![KeyShareEntry {
                        named_group: NamedGroup::x25519,
                        length: U16(32),
                        key_exchange: vec![
                            0xC9, 0x95, 0x87, 0x67, 0xE3, 0x8D, 0x0D, 0x6E, 0xF9, 0x5A, 0x71, 0x97,
                            0xAE, 0xF7, 0x95, 0x23, 0x6A, 0x0E, 0xB3, 0x4B, 0x30, 0x43, 0x9B, 0x93,
                            0xBF, 0xAF, 0x25, 0xAB, 0x75, 0xEF, 0x40, 0x10,
                        ],
                    }],
                },
            })),
        };
        let supported_versions = Extension {
            extension_type: ExtensionType::SupportedVersions,
            length: U16(5),
            payload: ExtensionPayload::SupportedVersions(
                SupportedVersions::ClientSupportedVersions(Vector {
                    size: U8(4),
                    elems: vec![ProtocolVersion::Tls_1_3, ProtocolVersion::Tls_1_2],
                }),
            ),
        };
        let server_name = Extension {
            extension_type: ExtensionType::ServerName,
            length: U16(19),
            payload: ExtensionPayload::ServerName(Vector {
                size: U16(17),
                elems: vec![ServerName {
                    name_type: NameType::Hostname,
                    name_length: U16(14),
                    name: "api.github.com".to_string(),
                }],
            }),
        };
        let client_hello_payload = ClientHello {
            legacy_version: ProtocolVersion::Tls_1_2,
            random: [
                0x30, 0x3E, 0xB7, 0xF6, 0x6F, 0xAC, 0x63, 0x01, 0xFE, 0x65, 0x33, 0xB1, 0xB6, 0xCC,
                0xBC, 0x63, 0x63, 0x67, 0x46, 0x17, 0x6B, 0xEC, 0x1A, 0x47, 0x2B, 0xB3, 0x8C, 0xBE,
                0xFC, 0x84, 0xAD, 0x11,
            ],
            legacy_session_id: Vector::<U8, U8> {
                size: U8(32),
                elems: vec![
                    U8(0x3E),
                    U8(0x80),
                    U8(0xEA),
                    U8(0xAB),
                    U8(0x85),
                    U8(0x9A),
                    U8(0xD5),
                    U8(0x3C),
                    U8(0x6B),
                    U8(0xFA),
                    U8(0x3A),
                    U8(0xB3),
                    U8(0x41),
                    U8(0x41),
                    U8(0x67),
                    U8(0x41),
                    U8(0xF1),
                    U8(0x0C),
                    U8(0x5F),
                    U8(0x5F),
                    U8(0xCE),
                    U8(0x12),
                    U8(0x67),
                    U8(0x05),
                    U8(0xD5),
                    U8(0xF3),
                    U8(0xB4),
                    U8(0x91),
                    U8(0xC3),
                    U8(0xED),
                    U8(0x73),
                    U8(0x06),
                ],
            },
            cipher_suites: Vector::<U16, CipherSuite> {
                size: U16(20),
                elems: vec![
                    CipherSuite::TLS_AES_256_GCM_SHA384,
                    CipherSuite::TLS_AES_128_GCM_SHA256,
                    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                    CipherSuite::UNKNOWN([0xC0, 0x2C]),
                    CipherSuite::UNKNOWN([0xC0, 0x2B]),
                    CipherSuite::UNKNOWN([0xCC, 0xA9]),
                    CipherSuite::UNKNOWN([0xC0, 0x30]),
                    CipherSuite::UNKNOWN([0xC0, 0x2F]),
                    CipherSuite::UNKNOWN([0xCC, 0xA8]),
                    CipherSuite::UNKNOWN([0x00, 0xFF]),
                ],
            },
            legacy_compression_methods: Vector::<U8, CompressionMethod> {
                size: U8(1),
                elems: vec![CompressionMethod::Null],
            },
            extensions: Vector::<U16, Extension> {
                size: U16(141),
                elems: vec![
                    signature_algorithms,
                    Extension {
                        extension_type: ExtensionType::Opaque([0x00, 0x0B]),
                        length: U16(2),
                        payload: ExtensionPayload::Opaque(vec![0x01, 0x00]),
                    },
                    status_request,
                    Extension {
                        extension_type: ExtensionType::Opaque([0x00, 0x17]),
                        length: U16(0),
                        payload: ExtensionPayload::Opaque(vec![]),
                    },
                    supported_groups,
                    psk_key_exchange_modes,
                    key_share,
                    Extension {
                        extension_type: ExtensionType::Opaque([0x00, 0x23]),
                        length: U16(0),
                        payload: ExtensionPayload::Opaque(vec![]),
                    },
                    supported_versions,
                    server_name,
                ],
            },
        };
        let client_hello = HandshakeMsg {
            msg_type: HandshakeType::ClientHello,
            length: U24(234),
            payload: crate::handshake::Payload::ClientHello(client_hello_payload),
        };
        let client_hello = OpaqueRecord {
            content_type: ContentType::Handshake,
            legacy_record_version: ProtocolVersion::Tls_1_0,
            length: U16(238),
            fragment: crate::record::Payload::Handshake(client_hello),
        };

        let mut buf = [0u8; 1 << 14];
        let written = client_hello.serialize(&mut buf).unwrap();
        assert_eq!(
            buf.get(..written).expect(UNEXPECTED_OUT_OF_BOUND_PANIC),
            &encoding,
        );
        assert_eq!(
            OpaqueRecord::deserialize(&encoding, ()),
            Ok((client_hello, written)),
        );
    }
}
