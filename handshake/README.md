- [x] Implement primitive types
    - [x] Test primitive types
- [ ] Implement `Record` type with opaque payload type
    - [ ] `ProtocolVersion`
    - [ ] `ContentType`
    - [ ] `RecordOverflowError` at deserialization
    - [ ] `Record` type
- [ ] Implement a binary using `rustls` and parse the handshake up to opaque records

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

# Primitive types
There are a few primitive data types that are the building blocks of any TLS message:

- integers  
integer types always have fixed sizes and are serialized using big-endian byte ordering
- enumerated  
each enumerated type has a fixed size, and the value of each variant is fixed
- fixed-sized arrays  
some array types have fixed sizes, such as `random` in `ClientHello`, which is always 32 bytes. Fixed-sized arrays don't need to prefix the data with its size
- variable-sized arrays (vectors)  
some array types have variale sizes, which means that its serialization is prefixed with the size of the data. The size of "size of data" is fixed

We will abstract the idea of sized serialization into a trait called `Deserializable`, which requires the implemented types to specify a method for writing into byte stream and parsing from byte streams.

```rust
pub trait Deserializable {
    pub fn serialize(&self, buffer: &mut [u8]) -> usize;
    pub fn deserialize(buffer: &[u8]) -> Result<(Self, usize), SomeErrorType>;
}
```

# Record layer
Each TLS message is encapsulated in a **record**, which has the following structure:

```rust
struct Record {
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    length: U16,
    paylod: Opaque,
}
```

Where `ContentType` and `ProtocolVersion` are both enumerated types encoding a small set of possible values:

```rust
/// Each value is a single byte
enum ContentType {
    Invalid,  // 0x00
    ChangeCipherSpec,  // 0x14
    Alert,  // 0x15
    Handshake,  // 0x16
    ApplicationData,  // 0x17
}

/// Each value is two-byte wide
enum ProtocolVersion {
    // Earlier versions are deprecated
    Tls_1_2,  // 0x0303
    Tls_1_3,  // 0x0304
}
```

The payload contains arbitrary bytes, although the maximal payload size is $2^{14}$ bytes. If the length field contains a value larger than the maximal payload size, the protocol should send an alert `RecordOverflow` (which should probably translate to some deserialization error).

Both clear messages and encrypted message follow the same structure, so a single struct should suffice for now. We will need to implement the cryptography parts first before we can handle encrypted records.
