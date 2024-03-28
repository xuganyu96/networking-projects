- [x] Parse record
    - [x] Parse content type
    - [x] Parse protocol version
    - [x] Parse u16
    - [x] Parse fragment as raw bytes
- [ ] Parse handshake message
    - [ ] Parse message type
    - [ ] Parse u24
    - [ ] Parse handshake payload as raw bytes
- [ ] Parse ClientHello

# Handshake
I want to build a TLS Handshake inspection tool in the form of a command-line application like `curl`:

```bash
handshake https://api.github.com/octocat
```

It should capture the outgoing and incoming messages during handshake (in the future maybe it can also capture application data and alerts), then output both the raw bytes (either as raw bytes or as HEX/Base64 encoded strings) and a human-readable format, such as YAML:

```yaml
ClientHello:
  legacy_version: "TLS1.3 (0x0303)"
  random: 0x0000000000000000....
  cipher_suites:
    - ChaCha20Poly1305Sha256
```

Not sure what use this project has, but it is a good exercise to write a TLS message parser in Rust. A challenge could be to make it copy-free using lifetime annotations.
