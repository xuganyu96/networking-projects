use std::error::Error;
use std::fmt::{Debug, Display};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeserializationError {
    /// The input buffer has fewer bytes than the type statically needs
    InsufficientBufferLength { expected: usize, found: usize },

    /// When parsing a vector, the buffer has fewer bytes than the vector's length indicates
    InsufficientVecData { expected: usize, found: usize },

    /// The encoded bytes do not match any valid enum variants,
    InvalidEnumValue,

    /// The length field of a record exceeds 2^14
    RecordOverflow,
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
    type Context: Copy;

    /// Has the same return type as io::Write::write
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Parse the input buffer into an instance of Self, return Self and the number of bytes
    /// consumed if parsing is successful.
    fn deserialize(
        buf: &[u8],
        context: Self::Context,
    ) -> Result<(Self, usize), DeserializationError>;
    /// Compute the number of bytes needed to encode the current instance at the time of calling
    /// this function
    fn size(&self) -> usize;
}

/// indicate that some element of this struct represent the integer zero
pub trait Zero {
    fn zero() -> Self;
}

pub trait DeserializableNum:
    Zero + std::ops::Add + Deserializable + Into<usize> + TryFrom<usize> + Copy
{
}
impl<T> DeserializableNum for T where
    T: Zero + std::ops::Add + Deserializable + Into<usize> + TryFrom<usize> + Copy
{
}
