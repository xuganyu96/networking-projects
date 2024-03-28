# Record layer
`Record` is the root layer struct. All other structs are sub-fields of the `Record` struct:

```rust
pub struct Record {
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    length: u16,
    fragment: RecordPayload,
}

pub enum RecordPayload {
    /// Unparsed raw bytes
    Opaque(Vec<u8>),

    /// Parsed handshake message
    Handshake(HandshakeMessage),

    /// TODO: parse application data
    /// TODO: parse alert
    /// TODO: parse change cipher spec
}
```


# Enums
