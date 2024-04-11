//! Variable-length vector
use crate::{Deserializable, DeserializationError};

/// Generic implementation of a variable-length vector
/// The size of the length field (U) is known at compile time, but the number of elements in the
/// payload is only known at runtime
pub struct Vector<T, U> {
    /// The number of bytes needed to encode the elements
    length: U,

    /// The elements themselves
    elems: Vec<T>,
}

impl<T: Deserializable, U: Copy + Deserializable + Into<usize>> Vector<T, U> {
    pub fn len(&self) -> usize {
        self.length.into()
    }

    pub fn elems_slice(&self) -> &[T] {
        &self.elems
    }
}

impl<T: Deserializable, U: Copy + Deserializable + Into<usize>> Deserializable for Vector<T, U> {
    fn try_deserialize(buffer: &[u8]) -> Result<(Self, usize), crate::DeserializationError> {
        let (length, length_size) = U::try_deserialize(buffer)?;
        let buffer = buffer
            .get(length_size..)
            .expect("Unexpected out of bound error");
        let length_usize: usize = length.into();

        let mut data_slice = match buffer.get(0..(length.into())) {
            None => {
                return Err(DeserializationError::insufficient_data(
                    length_usize,
                    buffer.len(),
                ));
            }
            Some(slice) => slice,
        };

        let mut elems: Vec<T> = vec![];
        while data_slice.len() > 0 {
            let (elem, elem_size) = T::try_deserialize(data_slice)?;
            data_slice = data_slice
                .get(elem_size..)
                .expect("Unexpected out-of-bound");
            elems.push(elem);
        }

        Ok((Vector { length, elems }, length_size + length_usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProtocolVersion, U8};

    #[test]
    fn deserialize_supported_versions() {
        let expected_versions = vec![ProtocolVersion::Tls1_3, ProtocolVersion::Tls1_2];
        let data = [0x04, 0x03, 0x04, 0x03, 0x03];
        let (supported_versions, consumed) =
            Vector::<ProtocolVersion, U8>::try_deserialize(&data).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(supported_versions.len(), 4);
        assert_eq!(supported_versions.elems, expected_versions);
    }
}
