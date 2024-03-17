//! A capture writer

use std::io::{Read, Write};


pub struct Capture<T> {
    io: T,
    ctr: usize,
}

impl<T: Read + Write> Capture<T> {
    pub fn new(io: T) -> Self {
        Self { io, ctr: 0 }
    }
}

impl<T: Read + Write> Read for Capture<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rxsize = self.io.read(buf)?;

        // Printout
        println!("RX: {} <<<<<<", self.ctr);
        self.ctr += 1;
        for byte in buf.get(0..rxsize).expect("Reader overflowed user buffer") {
            print!("{:02X}", byte);
        }
        println!("");

        return Ok(rxsize);
    }
}

impl<T: Read + Write> Write for Capture<T> {
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("TX: {} >>>>>>", self.ctr);
        self.ctr += 1;
        for byte in buf {
            print!("{:02X}", byte);
        }
        println!("");
        self.io.write(buf)
    }
}
