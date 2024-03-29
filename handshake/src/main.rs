use clap::{Parser, ValueEnum};
use rustls::ClientConnection;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Debug, ValueEnum, Clone)]
enum CaptureFormat {
    YAML,
    Hex,
    Base64,
    Raw,
}

/// Perform a TLS handshake, then gracefully drop the connection.
/// Capture the TLS metadata and write to the specified output in the specified format
#[derive(Debug, Parser)]
struct Args {
    /// Captured TLS metadata is encoded in Yaml, hex, base64, or raw bytes
    #[arg(long)]
    format: CaptureFormat,

    /// If a file is specified, captured TLS metadata will be written to the file
    /// Otherwise, capture is written to stdout
    #[arg(short)]
    out: Option<String>,

    /// The server to connect to
    url: String,
}

/// Wraps around the input stream and write the I/O data to the writer
struct HexCapture<T, U> {
    io: T,
    capture: U,
}

impl<T: Read + Write, U: Write> HexCapture<T, U> {
    fn new(io: T, capture: U) -> Self {
        Self { io, capture }
    }
}

impl<T: Read + Write, U: Write> Read for HexCapture<T, U> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rxsize = self.io.read(buf)?;

        // TODO: Capture structs should have a unified way to "capture bytes"
        // Capture failure should not cause the underlying read to fail
        buf.get(0..rxsize)
            .expect("Unexpected out of range error")
            .iter()
            .enumerate()
            .for_each(|(i, byte)| {
                let _ = write!(self.capture, "{:02X}", byte);
                if i < rxsize - 1 {
                    let _ = write!(self.capture, " ");
                } else {
                    let _ = writeln!(self.capture);
                }
            });

        return Ok(rxsize);
    }
}

impl<T: Write, U: Write> Write for HexCapture<T, U> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let txsize = self.io.write(buf)?;

        buf.get(0..txsize)
            .expect("Unexpected out of range error")
            .iter()
            .enumerate()
            .for_each(|(i, byte)| {
                let _ = write!(self.capture, "{:02X}", byte);
                if i < txsize - 1 {
                    let _ = write!(self.capture, " ");
                } else {
                    let _ = writeln!(self.capture);
                }
            });

        return Ok(txsize);
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

/// Create TLS connection and TCP connection
fn tls_connect_with_capture(server_name: &str) -> (ClientConnection, TcpStream) {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let tcp_addr = format!("{server_name}:443");
    let server_name = server_name.to_string().try_into().unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let sock = TcpStream::connect(tcp_addr).unwrap();
    return (conn, sock);
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let writer: Box<dyn Write> = match args.out {
        None => Box::new(std::io::stdout()),
        Some(path) => Box::new(std::fs::File::create(path)?),
    };

    let (mut conn, sock) = tls_connect_with_capture(&args.url);
    let mut sock = match args.format {
        CaptureFormat::Hex => HexCapture::new(sock, writer),
        _ => return Err("Other format not ready yet".into()),
    };

    conn.complete_io(&mut sock)?;
    conn.send_close_notify();
    conn.complete_io(&mut sock)?;

    return Ok(());
}
