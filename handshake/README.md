- [x] Implement deserialization trait
- [x] Implement primitive types: integers and vectors
- [x] Implement `Record` type with opaque payload type
- [x] Implement `ClientHello` parsing, except for some obscure extensions that are not strictly necessary
- [ ] generating and sending a `ClientHello`

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

# Serialization and deserialization
TLS is a network protocol: at the end of the day, everything will need to be converted into a sequence of bytes, and everything will need to be parsed from a sequence of bytes. A common set of API is thus necessary for capturing the aspect of data structures being serializable and deserializable.

I choose to capture this aspect of TLS data structures in a trait `Deserializable` which includes the following components:

```rust
pub trait Deserializable {
    type Context;
    fn serialize(&self, buf: &mut [u8]) -> std::io::Result;
    fn deserialize(buf: &[u8], context: Self::Context) -> Result<(Self, usize), DeserializationError>;
}
```

`Context` is worth some explanation. In TLS there are some data structures that change their internal layout depending on contextual information: is the record encrypted? is it the client or the server reading the message? For example, the handshake extension `supported_versions` is a vector of `ProtocolVersion` in `ClientHello`, but is a single `ProtocolVersion` in `ServerHello`, though they both have the same extension type, so it is not trivial to implement them as separate extensions. Instead, we can specify that when parsing bytes, the `supported_versions` extension require the caller to pass in the necessary contextual information, in this case `HandshakeType`, which can be either `ClientHello` or `ServerHello`.

```rust
pub enum SupportedVersions {
    ClientSupportedVersions(Vector<U8, ProtocolVersion>),
    ServerSupportedVersions(ProtocolVersion),
}

impl Deserializable for SupportedVersions {
    type Context = HandshakeType;

    fn deserialize(buf: &[u8], context: Self::Context) -> {
        // ...
        match context {
            HandshakeType::ClientHello => {
                // ... parse into vector of ProtocolVersions ...
            },
            HandshakeType::ServerHello => {
                // ... parse into a single ProtocolVersion ...
            }
        }
    }
}
```

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

## Encrypted records
In a typical TLS conversation, after `ClientHello` and `ServerHello`, the two parties have established a shared secret and can exchange encrypted records. Since I designed the `deserialize` function to be unaware of the context, it would be up to the caller to choose whether it is parsing a plaintext record (payload will be parsed into the higher level struct at `deserialize`) or an encrypted record (payload will first be parsed into opaque fragment, then decrypted, then parsed into higher level struct).  

This also means that there will be two structs `TLSPlaintext` and `TLSCiphertext`, where the payload field of `TLSCiphertext` is a `TLSInnerPlaintext`, which differ from the `TLSPlaintext` in its structure.

For now we will not worry about the API design for differentiating plaintext from ciphertext records.

Some ideas:

```rust
struct TLSPlaintext {
    content_type: ContentType,
    legacy_protocol_version: ProtocolVersion,
    length: U16,
    payload: Payload,
}

enum PlaintextPayload {
    HandshakeMsg,
    Alert,
    ApplicationData,

    /// Testing purpose only
    Opaque,
}

impl TLSPlaintext {
    fn deserialize(buf: &[u8]) -> Self {
        // based on the value of content_type, the fragment can be passed into higher level struct parsing
        // so the returned struct will have the complete structure
    }
}

enum CiphertextPayload {
    Ciphertext,
    TLSInnerPlaintext(TLSInnerPlaintext),
}

struct TLSCiphertext {
    content_type: ContentType,
    legacy_protocol_version: ProtocolVersion,
    length: U16,
    encrypted_record: CiphertextPayload,
}

impl TLSCiphertext {
    fn deserialize(buf: &[u8]) -> Self {
        // at deserialization, first parse into Payload::Opaque,
        // decryption and further parsing will happen with another function call
    }

    fn decrypt(&self, key: ???) -> Self {
        // decrypt the opaque record AND parse into higher level structs
    }
}

/// TODO: When parsing inner plaintext, need to read the input buffer backwards until reaching a byte that contains valid content_type encoding
struct TLSInnerPlaintext {
    content: Payload,
    content_type: ContentType,
    /// The inner representation of padding will only be a count to save memory
    zeros: U16,
}
```
