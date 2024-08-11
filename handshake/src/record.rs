//! Record Layer
use crate::handshake::HandshakeMsg;
use crate::primitives::{ContentType, ProtocolVersion, U16};
use crate::traits::{Deserializable, DeserializationError};
use crate::{MAX_RECORD_LENGTH, UNEXPECTED_OUT_OF_BOUND_PANIC};
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Opaque(Vec<u8>),
    Handshake(HandshakeMsg),
}

impl Deserializable for Payload {
    /// Payload always first serialize into opaque bytes. Higher level parsing should be left to
    /// other methods
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Opaque(fragment) => buf.write(&fragment),
            Self::Handshake(msg) => msg.serialize(buf),
        }
    }

    /// The Payload field by itself does not know what kind of payload it should be, neither does
    /// it know how many bytes to consume. Instead, it relies on the caller to supply it with the
    /// correct slice and perform further parsing into the appropriate payload type
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        Ok((Self::Opaque(buf.to_vec()), buf.len()))
    }
}

/// The record type is the top-level abstraction.
///
/// TODO: this is a literal translation of the specification. There could be some deviation (not
/// sure if any good though): use Vector<U16, U8>, use fragment: &[u8], use fragment: [u8; 1 << 14]
/// TODO: maybe TLSPlaintext is a more suitable name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRecord {
    pub content_type: ContentType,

    /// per RFC 8446: must be set to 0x0303 for all records generated by a TLS 1.3 implementation
    /// other than an initial ClientHello, where it may also be 0x0301 for compatibility purposes
    pub legacy_record_version: ProtocolVersion,

    /// the length of the fragment in bytes. Must not exceed 2^14 bytes; an endpoint receiving a
    /// record that exceeds thislength must terminate the connection with a "record_overflow" alert
    pub length: U16,

    pub fragment: Payload,
}

impl Deserializable for OpaqueRecord {
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
        written += self.fragment.serialize(&mut buf)?;

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
        if fragment_size > MAX_RECORD_LENGTH {
            return Err(DeserializationError::RecordOverflow);
        }
        if buf.len() < fragment_size {
            return Err(DeserializationError::insufficient_vec_data(
                fragment_size,
                buf.len(),
            ));
        }
        let fragment = buf
            .get(..fragment_size)
            .expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let payload: Payload = match content_type {
            ContentType::Handshake => {
                let (msg, _) = HandshakeMsg::deserialize(fragment)?;
                Payload::Handshake(msg)
            }
            ContentType::Opaque => Payload::Opaque(fragment.to_vec()),
            _ => todo!(),
        };

        return Ok((
            Self {
                content_type,
                legacy_record_version,
                length,
                fragment: payload,
            },
            content_size + version_size + length_size + fragment_size,
        ));
    }
}

impl std::fmt::Display for OpaqueRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<OpaqueRecord type={:?} protocol={} [{} bytes]>",
            self.content_type, self.legacy_record_version, self.length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_serde() {
        let record = OpaqueRecord {
            content_type: ContentType::Opaque,
            legacy_record_version: ProtocolVersion::Tls_1_3,
            length: U16(5),
            fragment: Payload::Opaque([0u8; 5].to_vec()),
        };
        let expected_buf = [0xFF, 3, 4, 0, 5, 0, 0, 0, 0, 0];
        let mut buf = [0u8; 10];
        record.serialize(&mut buf).unwrap();
        assert_eq!(buf, expected_buf);
        assert_eq!(OpaqueRecord::deserialize(&expected_buf), Ok((record, 10)));

        assert_eq!(
            OpaqueRecord::deserialize(&[22, 3, 4, 0, 6, 0, 0, 0, 0, 0]),
            Err(DeserializationError::insufficient_vec_data(6, 5)),
        );
        assert_eq!(
            OpaqueRecord::deserialize(&[22, 3, 4, 1 << 7, 0, 0, 0, 0, 0, 0]),
            Err(DeserializationError::RecordOverflow),
        );
    }
}
