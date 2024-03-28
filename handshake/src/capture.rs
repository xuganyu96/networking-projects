//! A capture writer

use std::io::{Read, Write};

/// A wrapper around some I/O struct, such as a TcpStream, that acts just like the underlying
/// struct. In addition, the data that were read or written will be captured and written into some
/// other writer, such as stdout or a log file
pub struct Capture<T> {
    /// The reader/writer that this struct captures the I/O
    io: T,

    /// Counts the number of captures
    ctr: usize,

    /// Where the captured data will be written
    sink: Box<dyn Write>,
}

impl<T: Read + Write> Capture<T> {
    pub fn new(io: T, sink: Box<dyn Write>) -> Self {
        Self { io, ctr: 0, sink }
    }
}

impl<T: Read> Read for Capture<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rxsize = self.io.read(buf)?;

        // Capture bytes into the sink
        writeln!(self.sink, "RX: {} <<<<<<", self.ctr)?;
        self.ctr += 1;
        for byte in buf.get(0..rxsize).expect("Reader overflowed user buffer") {
            write!(self.sink, "{:02X}", byte)?;
        }
        writeln!(self.sink, "")?;

        return Ok(rxsize);
    }
}

impl<T: Write> Write for Capture<T> {
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        writeln!(self.sink, "TX: {} >>>>>>", self.ctr)?;
        self.ctr += 1;
        for byte in buf {
            write!(self.sink, "{:02X}", byte)?;
        }
        writeln!(self.sink, "")?;
        self.io.write(buf)
    }
}
