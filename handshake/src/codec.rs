//! The Codec trait
use std::io::Write;

/// Data structure can be written onto a buffer and be extracted from a buffer
/// TODO: make extract return Result rather than Error
pub trait Codec {
    type Data: Sized;

    /// Write the byte representation of self onto the writer
    fn encode(&self, buffer: &mut impl Write) -> std::io::Result<usize>;

    /// Read from the beginning of the buffer. If a piece of data can be parsed, return the piece
    /// of data and the remainder of the buffer.
    fn extract(buffer: &[u8]) -> Option<(Self::Data, &[u8])>;
}
