# Handshake
I want to better understand the TLS handshake protocol by building **a library for parsing TLS messages**. From here this project can also become a simple TLS client that allows users to tinker with the parameters of a TLS handshake.

TLS 1.3 is specified in [RFC 8846](https://datatracker.ietf.org/doc/html/rfc8446). A [sample handshake](./sample-handshake.md) was captured using [rustls](https://github.com/rustls/rustls).


# An overview of a TLS handshake
The Transport Layer Security is a network communication protocol with which two parties can establish a secure channel over an insecure communication method. The party that initiated the connection is usually called the client, and the other party is called the server. After a TCP connection is established, the client and the server perform a handshake in which the two parties exchange their cryptographic parameters, the server authenticates itself to the client, and the client optionally authenticates itself to the server. After the handshake is completed, the two parties will have established a shared secret key, from which point they can communicate securely.

The handshake involves client and server exchanging a number of messages:

- Client and server exchange `ClientHello` and `ServerHello`, from which a session key can be established. Subsequent communications are encrypted using the session key
- Server authenticates itself to the client using `Certificate`, `CertificateVerify`
- Client optionally authenticates itself using the same set of messages
- Client and server confirm that they indeed have the same session key using `Finished`
- Handshake is completed, client and server begin exchanging application data
