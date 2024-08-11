//! Handshake
use crate::{
    primitives::U24,
    traits::{Deserializable, DeserializationError},
    UNEXPECTED_OUT_OF_BOUND_PANIC,
};
use std::io::Write;

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
}

impl Deserializable for Payload {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
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
    msg_type: HandshakeType,
    length: U24,
    payload: Payload,
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
        buf = buf.get(..U24::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);

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
}
