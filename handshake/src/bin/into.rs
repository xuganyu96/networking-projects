use std::{
    num::TryFromIntError,
    ops::{Add, Deref},
};

#[derive(Debug)]
struct U16(u16);

impl U16 {
    fn zero() -> Self {
        Self(0)
    }
}

impl Deref for U16 {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add for U16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl TryFrom<usize> for U16 {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let truncate = value.try_into()?;
        Ok(Self(truncate))
    }
}

fn main() {
    let elem_size = 999usize;
    let mut truncate = U16::zero();
    println!("{:?}", &truncate);

    truncate = truncate + elem_size.try_into().unwrap();
    println!("{:?}", &truncate);
}
