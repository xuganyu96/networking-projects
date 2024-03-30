- [x] Capture TLS handshake in hex
- [ ] Read the captured hex and decide which structs to implement
- [ ] Implement ClientHello parsing

# Handshake
Command-line TLS client

```bash
# Specify capture format and output path
handshake --format [hex|b64|yaml] -o some/file <url>
```
