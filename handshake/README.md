- [x] Capture TLS handshake in hex
- [x] Read the captured hex and decide which structs to implement
- [x] Implement ClientHello parsing
    - [x] Consider providing a generic variable-length vector implementation
    - [x] Implement the extensions found in [sample handshake](./sample-handshake.md)
- [ ] Modify the binary so that it prints ClientHello in details and the rest of the messages in opaque
- [ ] Refactor for better organization
- [ ] Implement ServerHello parsing

**Niceties**:
- Implement `Serialize` and `Deserialize` for the data structures
- Use a procedural macro to automatically implement serialization/deserialization for
    - composite structs
    - simple enums

# Handshake
Command-line TLS client

```bash
# Specify capture format and output path
handshake --format [hex|b64|yaml] -o some/file <url>
```

# Generic variable-length vector
```rust
/// T is the element type (e.g. ProtocolVersion in supported_versions), L is 
/// the length type (e.g. U24). When deserializing, first deserialize the length
/// field, then repeatedly deserialize the elements
pub struct Vector<T, L> {
    elems: Vec<T>,
}
```

If there are fewer bytes remaining than the length field indicates, return "InsufficientData", otherwise parse the rest of the array and let the element parsing raise the appropriate error.
