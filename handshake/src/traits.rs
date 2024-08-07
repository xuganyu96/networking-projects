use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeserializationError {
    /// The input buffer has fewer bytes than the type statically needs
    InsufficientBufferLength { expected: usize, found: usize },

    /// When parsing a vector, the buffer has fewer bytes than the vector's length indicates
    InsufficientVecData { expected: usize, found: usize },

    /// The encoded bytes do not match any valid enum variants,
    InvalidEnumValue,
}

impl DeserializationError {
    pub fn insufficient_buffer_length(expected: usize, found: usize) -> Self {
        Self::InsufficientBufferLength { expected, found }
    }

    pub fn insufficient_vec_data(expected: usize, found: usize) -> Self {
        Self::InsufficientVecData { expected, found }
    }
}

impl Display for DeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DeserializationError {}

pub trait Deserializable
where
    Self: Sized,
{
    /// Has the same return type as io::Write::write
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError>;
}
