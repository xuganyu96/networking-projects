//! The Codec trait
use std::io::Write;

/// 
pub enum DecodeError {
}

/// Data structure can be written onto a buffer and be extracted from a buffer
/// TODO: make extract return Result rather than Error
pub trait Codec {
    type Data: Sized;

    /// Compute the number of bytes needed to encode this struct
    fn encode_size(&self) -> usize;

    /// Write the byte representation to the provided buffer
    fn encode_to_bytes(&self, buffer: &mut [u8]) -> std::io::Result<usize>;

    /// Write the byte representation of self onto the writer
    ///
    /// The default implementation allocates a Vec; custom implementation can save the allocation
    fn encode_to_writer(&self, writer: &mut impl Write) -> std::io::Result<usize> {
        let mut buffer: Vec<u8> = vec![];
        self.encode_to_bytes(&mut buffer)?;
        writer.write(&buffer)
    }

    /// Read from the beginning of the buffer. If a piece of data can be parsed, return the piece
    /// of data and the remainder of the buffer.
    fn extract(buffer: &[u8]) -> Result<(Self::Data, &[u8]), DecodeError>;
}
