use crate::traits::{Deserializable, DeserializationError};
use std::io::Write;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U8(u8);

impl U8 {
    pub const BYTES: usize = 1;
}

impl Deserializable for U8 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        return Ok((Self(buf[0]), Self::BYTES));
    }
}

impl From<U8> for usize {
    fn from(value: U8) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U16(u16);

impl U16 {
    pub const BYTES: usize = 2;
}

impl Deserializable for U16 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u16::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl From<U16> for usize {
    fn from(value: U16) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U24(u32);

impl U24 {
    pub const BYTES: usize = 3;
}

impl Deserializable for U24 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    /// Only read the first three bytes from the input buffer and parses them into a u32
    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; 4];
        be_bytes
            .get_mut(1..4)
            .expect("Unexpected out-of-bound error")
            .copy_from_slice(&buf[0..Self::BYTES]);
        let val = u32::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U24 {
    fn into(self) -> usize {
        self.0.try_into().expect("Unexpected overflow")
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U32(u32);

impl U32 {
    pub const BYTES: usize = 4;
}

impl Deserializable for U32 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u32::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U32 {
    fn into(self) -> usize {
        self.0.try_into().expect("Unexpected overflow")
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct U64(u64);

impl U64 {
    pub const BYTES: usize = 8;
}

impl Deserializable for U64 {
    fn serialize(&self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        buf.write(&self.0.to_be_bytes())
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        if buf.len() < Self::BYTES {
            return Err(DeserializationError::insufficient_buffer_length(
                Self::BYTES,
                buf.len(),
            ));
        }
        let mut be_bytes = [0u8; Self::BYTES];
        be_bytes.copy_from_slice(&buf[0..Self::BYTES]);
        let val = u64::from_be_bytes(be_bytes);

        Ok((Self(val), Self::BYTES))
    }
}

impl Into<usize> for U64 {
    fn into(self) -> usize {
        self.0.try_into().expect("Unexpected overflow")
    }
}

/// T is the length type; U is the element type
pub struct Vector<T, U> {
    /// The number of bytes needed to serialize and deserialize the vector
    size: T,
    /// The individual elements
    elems: Vec<U>,
}

impl<T, U> Vector<T, U> {
    pub fn elems_slice(&self) -> &[U] {
        &self.elems
    }
}

impl<T, U> Deserializable for Vector<T, U>
where
    T: Deserializable + Copy,
    U: Deserializable,
    usize: From<T>, // TODO: is it better to qualify with Into<usize>?
{
    /// First serialize the size, then serialize the data
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        // TODO: need to check that buf actually has enough lenth left
        written += self.size.serialize(&mut buf[written..])?;
        for elem in self.elems_slice() {
            written += elem.serialize(&mut buf[written..])?;
        }
        return Ok(written);
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, usize), DeserializationError> {
        let mut written: usize = 0;
        let (datalen, consumed) = T::deserialize(buf)?;
        let datalen_usize: usize = datalen.into();
        written += datalen_usize;
        let mut dataslice = &buf[consumed..consumed + datalen_usize];

        if dataslice.len() < datalen_usize {
            return Err(DeserializationError::insufficient_vec_data(
                datalen_usize,
                dataslice.len(),
            ));
        }

        let mut elems: Vec<U> = vec![];
        while dataslice.len() > 0 {
            let (elem, elem_size) = U::deserialize(dataslice)?;
            elems.push(elem);
            dataslice = &dataslice[elem_size..];
        }

        let vector = Self {
            size: datalen,
            elems,
        };

        Ok((vector, written))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize a vector with some simple types, then deserialize
    #[test]
    fn vector_serde() {
        // empty vector
        let vector = Vector::<U8, U8> {
            size: U8(0),
            elems: vec![],
        };
        let mut buffer = [0u8; 1];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 1);
        assert_eq!(buffer, [0]);

        // non-empty vector
        let vector = Vector::<U8, U8> {
            size: U8(2),
            elems: vec![U8(255), U8(255)],
        };
        let mut buffer = [0u8; 3];
        let written = vector.serialize(&mut buffer).unwrap();
        assert_eq!(written, 3);
        assert_eq!(buffer, [2, 255, 255]);
    }
}
