# Handshake
I want to build a TLS Handshake inspection tool in the form of a command-line application like `curl`:

```
handshake --[yaml|hex|b64] -o some_file <url>
```

It should capture the outgoing and incoming messages during handshake (in the future maybe it can also capture application data and alerts), then output both the raw bytes (either as raw bytes or as HEX/Base64 encoded strings) and a human-readable format, such as YAML:

```yaml
ClientHello:
  legacy_version: "TLS1.3 (0x0303)"
  random: 0x0000000000000000....
  cipher_suites:
    - ChaCha20Poly1305Sha256
```
