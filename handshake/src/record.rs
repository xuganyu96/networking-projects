//! A record is a single TLS message and the top layer abstraction
use crate::enums::{ContentType, ProtocolVersion};

pub enum Payload {}

/// Top-layer struct that abstract a single TLS message
pub struct Record {
    content_type: ContentType,
    legacy_record_version: ProtocolVersion,
    length: u16,
    fragment: Payload,
}

impl Record {
    pub fn new(
        content_type: ContentType,
        legacy_record_version: ProtocolVersion,
        length: u16,
        fragment: Payload,
    ) -> Self {
        Self {
            content_type,
            legacy_record_version,
            length,
            fragment,
        }
    }
}
