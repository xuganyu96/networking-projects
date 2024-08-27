//! Alerts
use crate::traits::{Deserializable, DeserializationError};
use crate::UNEXPECTED_OUT_OF_BOUND_PANIC;
use std::io::Write;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AlertLevel {
    Warning,
    Fatal,
}

impl AlertLevel {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::Warning => [1],
            Self::Fatal => [2],
        }
    }
}

impl Deserializable for AlertLevel {
    type Context = ();

    fn size(&self) -> usize {
        Self::BYTES
    }

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
        let data_slice = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let level = match data_slice {
            &[1] => Self::Warning,
            &[2] => Self::Fatal,
            _ => {
                return Err(DeserializationError::InvalidEnumValue);
            }
        };

        Ok((level, Self::BYTES))
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AlertDescription {
    close_notify,
    unexpected_message,
    bad_record_mac,
    record_overflow,
    handshake_failure,
    bad_certificate,
    unsupported_certificate,
    certificate_revoked,
    certificate_expired,
    certificate_unknown,
    illegal_parameter,
    unknown_ca,
    access_denied,
    decode_error,
    decrypt_error,
    protocol_version,
    insufficient_security,
    internal_error,
    inappropriate_fallback,
    user_canceled,
    missing_extension,
    unsupported_extension,
    unrecognized_name,
    bad_certificate_status_response,
    unknown_psk_identity,
    certificate_required,
    no_application_protocol,
}

impl AlertDescription {
    pub const BYTES: usize = 1;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        match self {
            Self::close_notify => [0],
            Self::unexpected_message => [10],
            Self::bad_record_mac => [20],
            Self::record_overflow => [22],
            Self::handshake_failure => [40],
            Self::bad_certificate => [42],
            Self::unsupported_certificate => [43],
            Self::certificate_revoked => [44],
            Self::certificate_expired => [45],
            Self::certificate_unknown => [46],
            Self::illegal_parameter => [47],
            Self::unknown_ca => [48],
            Self::access_denied => [49],
            Self::decode_error => [50],
            Self::decrypt_error => [51],
            Self::protocol_version => [70],
            Self::insufficient_security => [71],
            Self::internal_error => [80],
            Self::inappropriate_fallback => [86],
            Self::user_canceled => [90],
            Self::missing_extension => [109],
            Self::unsupported_extension => [110],
            Self::unrecognized_name => [112],
            Self::bad_certificate_status_response => [113],
            Self::unknown_psk_identity => [115],
            Self::certificate_required => [116],
            Self::no_application_protocol => [120],
        }
    }
}

impl Deserializable for AlertDescription {
    type Context = ();

    fn size(&self) -> usize {
        Self::BYTES
    }

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
        let data_slice = buf.get(..Self::BYTES).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let description = match data_slice {
            &[0] => Self::close_notify,
            &[10] => Self::unexpected_message,
            &[20] => Self::bad_record_mac,
            &[22] => Self::record_overflow,
            &[40] => Self::handshake_failure,
            &[42] => Self::bad_certificate,
            &[43] => Self::unsupported_certificate,
            &[44] => Self::certificate_revoked,
            &[45] => Self::certificate_expired,
            &[46] => Self::certificate_unknown,
            &[47] => Self::illegal_parameter,
            &[48] => Self::unknown_ca,
            &[49] => Self::access_denied,
            &[50] => Self::decode_error,
            &[51] => Self::decrypt_error,
            &[70] => Self::protocol_version,
            &[71] => Self::insufficient_security,
            &[80] => Self::internal_error,
            &[86] => Self::inappropriate_fallback,
            &[90] => Self::user_canceled,
            &[109] => Self::missing_extension,
            &[110] => Self::unsupported_extension,
            &[112] => Self::unrecognized_name,
            &[113] => Self::bad_certificate_status_response,
            &[115] => Self::unknown_psk_identity,
            &[116] => Self::certificate_required,
            &[120] => Self::no_application_protocol,
            _ => {
                return Err(DeserializationError::InvalidEnumValue);
            }
        };

        Ok((description, Self::BYTES))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

impl Alert {
    pub const BYTES: usize = AlertLevel::BYTES + AlertDescription::BYTES;
}

impl Deserializable for Alert {
    type Context = ();

    fn size(&self) -> usize {
        Self::BYTES
    }

    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        written += self.level.serialize(buf)?;
        written += self.description.serialize(buf)?;

        Ok(written)
    }

    fn deserialize(
        mut buf: &[u8],
        _context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let (level, level_size) = AlertLevel::deserialize(buf, ())?;
        buf = buf.get(level_size..).expect(UNEXPECTED_OUT_OF_BOUND_PANIC);
        let (description, description_size) = AlertDescription::deserialize(buf, ())?;

        Ok((Self { level, description }, level_size + description_size))
    }
}
