//! Handshake
use crate::{
    extensions::Extension,
    primitives::{CipherSuite, CompressionMethod, ProtocolVersion, Vector, U16, U24, U8},
    traits::{Deserializable, DeserializationError},
    UNEXPECTED_OUT_OF_BOUND_PANIC,
};
use std::io::Write;

pub const RANDOM_SIZE: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HandshakeType {
    /// 0x01
    ClientHello,

    /// 0x02
    ServerHello,

    /// 0xFF, special type for testing purpose only
    Opaque,
}

impl HandshakeType {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Opaque => [0xFF],
            Self::ClientHello => [1],
            Self::ServerHello => [2],
        }
    }
}

impl Deserializable for HandshakeType {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.to_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), crate::traits::DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }

        let hstype = match buf[..Self::BYTES] {
            [0xFF] => Self::Opaque,
            [1] => Self::ClientHello,
            [2] => Self::ServerHello,
            _ => {
                return Err(DeserializationError::InvalidEnumValue);
            }
        };

        Ok((hstype, Self::BYTES))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Opaque(Vec<u8>),
    ClientHello(ClientHello),
}

impl Deserializable for Payload {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
            Self::ClientHello(client_hello) => client_hello.serialize(buf),
        }
    }

    /// the payload field by itself doesn't know what type of payload it should be, so it
    /// defaults to opaque. The caller is responsible for further parsing
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), crate::traits::DeserializationError> {
        Ok((Self::Opaque(buf.to_vec()), buf.len()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMsg {
    pub msg_type: HandshakeType,
    pub length: U24,
    pub payload: Payload,
}

impl Deserializable for HandshakeMsg {
    fn deserialize(mut buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let static_size = HandshakeType::BYTES + U24::BYTES;
        if buf.len() < static_size {
            return Err(DeserializationError::insufficient_buffer_length(
                static_size,
                buf.len(),
            ));
        }

        let (msg_type, _) = HandshakeType::deserialize(buf)?;
        buf = buf
            .get(HandshakeType::BYTES..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (length, _) = U24::deserialize(buf)?;
        buf = buf.get(U24::BYTES..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        let payload_size: usize = length.into();
        // TODO: no need to check payload size overflow?
        if buf.len() < payload_size {
            return Err(DeserializationError::insufficient_vec_data(
                payload_size,
                buf.len(),
            ));
        }
        let payload_slice = buf
            .get(..payload_size)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let payload = match msg_type {
            HandshakeType::Opaque => {
                let (opaque_payload, _) = Payload::deserialize(payload_slice)?;
                opaque_payload
            }
            HandshakeType::ClientHello => {
                let (client_hello, _) = ClientHello::deserialize(payload_slice)?;
                Payload::ClientHello(client_hello)
            }
            _ => todo!(),
        };

        Ok((
            Self {
                msg_type,
                length,
                payload,
            },
            HandshakeType::BYTES + U24::BYTES + payload_size,
        ))
    }

    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let msg_type_size = self.msg_type.serialize(&mut buf)?;
        buf = buf
            .get_mut(msg_type_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let length_size = self.length.serialize(&mut buf)?;
        buf = buf
            .get_mut(length_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let payload_size = self.payload.serialize(&mut buf)?;

        Ok(msg_type_size + length_size + payload_size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: ProtocolVersion,
    pub random: [u8; RANDOM_SIZE],
    pub legacy_session_id: Vector<U8, U8>,
    pub cipher_suites: Vector<U16, CipherSuite>,
    pub legacy_compression_methods: Vector<U8, CompressionMethod>,
    pub extensions: Vector<U16, Extension>,
}

impl Deserializable for ClientHello {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let version_size = self.legacy_version.serialize(buf)?;
        buf = buf
            .get_mut(version_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        buf.write(&self.random)?;
        let session_id_size = self.legacy_session_id.serialize(buf)?;
        buf = buf
            .get_mut(session_id_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let cipher_suites_size = self.cipher_suites.serialize(buf)?;
        buf = buf
            .get_mut(cipher_suites_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let compression_methods_size = self.legacy_compression_methods.serialize(buf)?;
        buf = buf
            .get_mut(compression_methods_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let extension_size = self.extensions.serialize(buf)?;

        Ok(version_size
            + RANDOM_SIZE
            + session_id_size
            + cipher_suites_size
            + compression_methods_size
            + extension_size)
    }

    fn deserialize(mut buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let (legacy_version, version_size) = ProtocolVersion::deserialize(buf)?;
        buf = buf
            .get(version_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        if buf.len() < RANDOM_SIZE {
            return Err(DeserializationError::insufficient_buffer_length(
                RANDOM_SIZE,
                buf.len(),
            ));
        }
        let mut random = [0u8; RANDOM_SIZE];
        random.copy_from_slice(buf.get(..RANDOM_SIZE).expect(UNEXPECTED_OUT_OF_BOUND_PANIC));
        buf = buf.get(RANDOM_SIZE..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

        let (legacy_session_id, session_id_size) = Vector::<U8, U8>::deserialize(buf)?;
        buf = buf
            .get(session_id_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (cipher_suites, cipher_suites_size) = Vector::<U16, CipherSuite>::deserialize(buf)?;
        buf = buf
            .get(cipher_suites_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (legacy_compression_methods, compression_methods_size) =
            Vector::<U8, CompressionMethod>::deserialize(buf)?;
        buf = buf
            .get(compression_methods_size..)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (extensions, extensions_size) = Vector::<U16, Extension>::deserialize(buf)?;

        let client_hello = ClientHello {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        };

        Ok((
            client_hello,
            version_size
                + RANDOM_SIZE
                + session_id_size
                + cipher_suites_size
                + compression_methods_size
                + extensions_size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_handshake_serde() {
        let msg = HandshakeMsg {
            msg_type: HandshakeType::Opaque,
            length: U24(5),
            payload: Payload::Opaque([0u8; 5].to_vec()),
        };
        let mut buf = [0u8; 9];
        msg.serialize(&mut buf).unwrap();
        assert_eq!(buf, [0xFF, 0, 0, 5, 0, 0, 0, 0, 0]);

        assert_eq!(
            HandshakeMsg::deserialize(&[0xFF, 0, 0, 0,]),
            Ok((
                HandshakeMsg {
                    msg_type: HandshakeType::Opaque,
                    length: U24(0),
                    payload: Payload::Opaque(vec!()),
                },
                4
            ))
        );
    }

    #[test]
    fn opaque_client_hello_serde() {
        let client_hello = ClientHello {
            legacy_version: ProtocolVersion::Tls_1_2,
            random: [1u8; RANDOM_SIZE],
            legacy_session_id: Vector::<U8, U8> {
                size: U8(0),
                elems: vec![],
            },
            cipher_suites: Vector::<U16, CipherSuite> {
                size: U16(0),
                elems: vec![],
            },
            legacy_compression_methods: Vector::<U8, CompressionMethod> {
                size: U8(0),
                elems: vec![],
            },
            extensions: Vector {
                size: U16(0),
                elems: vec![],
            },
        };
        let mut buf = [0u8; 999];
        let client_hello_size = client_hello.serialize(&mut buf).unwrap();
        assert_eq!(
            buf.get(..client_hello_size).unwrap(),
            &[
                3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
            ],
        );

        assert_eq!(
            ClientHello::deserialize(&buf[..client_hello_size]),
            Ok((client_hello, client_hello_size))
        );
    }
}
