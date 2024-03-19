use clap::Parser;
use handshake::capture::Capture;
use rustls::{self, ClientConfig, ClientConnection, RootCertStore};
use std::{fs::File, net::TcpStream, sync::Arc};

/// Performs a TLS handshake, then drop the connection immediately
#[derive(Debug, Parser)]
struct Args {
    /// Output the captured to this file. If the file does not exist, it will be created.
    /// If left out, the captured bytes will be written to stdout
    #[arg(short = 'o')]
    output: Option<String>,

    url: String,
}

fn main() {
    let args = Args::parse();

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = args.url.clone().try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let sock = TcpStream::connect(&format!("{}:443", &args.url)).unwrap();

    let mut sock = match args.output {
        None => Capture::new(sock, Box::new(std::io::stdout())),
        Some(path) => {
            let file = File::create(path).unwrap();
            Capture::new(sock, Box::new(file))
        }
    };

    let tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.conn.complete_io(tls.sock).unwrap();
    tls.conn.send_close_notify();
    tls.conn.complete_io(tls.sock).unwrap();
}
