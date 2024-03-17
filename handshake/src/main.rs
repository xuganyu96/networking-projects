// use std::io::{Write, Read, stdout};
use std::{net::TcpStream, sync::Arc};
use handshake::capture::Capture;
use rustls::{self, ClientConfig, ClientConnection, RootCertStore};


fn main() {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into()
    };
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "api.github.com".try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let sock = TcpStream::connect("api.github.com:443").unwrap();
    let mut sock = Capture::new(sock);
    let tls = rustls::Stream::new(&mut conn, &mut sock);
    
    tls.conn.complete_io(tls.sock).unwrap();
    tls.conn.send_close_notify();
    tls.conn.complete_io(tls.sock).unwrap();
}
