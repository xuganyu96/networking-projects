# Sample client hello
```yaml
content_type: handshake (0x16)
protocol_version: TLS 1.0 (0x0301)  # this is for compatibility
length: 238 (0x00EE)
payload:
    message_type: client_hello (0x01)
    length: 234 (0x0000EA)
    payload:
    protocol_version: TLS 1.2 (0x0303)  # this is for compatibility
    random: 0x303EB7F66FAC6301FE6533B1B6CCBC63636746176BEC1A472BB38CBEFC84AD11
    legacy_session_id:  # this is a vector between 0 and 32 bytes
        length: 32 (0x20)
        payload: 0x3E80EAAB859AD53C6BFA3AB341416741F10C5F5FCE126705D5F3B491C3ED7306
    cipher_suites:
        length: 20 (0x0014)
        suites:  # this is ranked by client's preference
        - TLS_AES_256_GCM_SHA384 (0x1302)
        - TLS_AES_128_GCM_SHA256 (0x1301)
        - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        # Below are TLS 1.2 cipher suites
        - TLS_ECDHE_RSA_AES128_GCM_SHA256 (0xC02C)
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xCCA9)
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xCCA8)
        # In TLS 1.2 this indicates client support for renegotiation
        # TLS 1.3 does not support renegotiation
        - TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)
    legacy_compression_methods:  # deprecated in TLS 1.3, always an empty list
        length: 1 (0x01)
        payload: 0x00
    extensions:
        length: 141 (0x008D)
        payload:
        - extension_type: signature_algorithms (0x000D)
          length: 22 (0x0016)
          supported_signature_algorithms:
            length: 20 (0x0014)
            payload:
                - ecdsa_secp521r1_sha512 (0x0603)
                - ecdsa_secp384r1_sha384 (0x0503)
                - ecdsa_secp256r1_sha256 (0x0403)
                - ed25519 (0x0807)
                - rsa_pss_rsae_sha512 (0x0806)
                - rsa_pss_rsae_sha384 (0x0805)
                - rsa_pss_rsae_sha256 (0x0804)
                - rsa_pkcs1_sha256 (0x0401)
                - rsa_pkcs1_sha384 (0x0501)
                - rsa_pkcs1_sha512 (0x0601)
        - extension_type: UNKNOWN (0x000B)
          length: 2 (0x0002)
          payload: 0x0100
        - extension_type: status_request (0x0005)
          length: 5 (0x0005)
          payload: 0x0100000000
        - extension_type: UNKNOWN (0x0017)
          length: 0 (0x0000)
          payload: null
        - extension_type: supported_groups (0x000A)
          length: 8 (0x0008)
          payload:
            length: 6 (0x0006)
            named_group_list:
            - x25519 (0x001D)
            - secp256r1 (0x0017)
            - secp384r1 (0x0018)
        - extension_type: psk_key_exchange_modes (0x002D)
          length: 2 (0x0002)
          payload:
            length: 1 (0x01)
            ke_modes:
            - psk_dhe_ke (0x01)
        - extension_type: key_share (0x0033)
          length: 38 (0x26)
          payload:
            length: 36 (0x24)
            client_shares:
            - group: x25519 (0x001D)
              length: 32 (0x0020)
              key_exchange: 0xC9958767E38D0D6EF95A7197AEF795236A0EB34B30439B93BFAF25AB75EF4010
        - extension_type: UNKNOWN (0x0023)
          length: 0 (0x0000)
          payload: null
        - extension_type: supported_versions (0x002B)
          length: 5 (0x0005)
          payload:
            length: 4 (0x04)
            versions:
            - TLS 1.3 (0x0304)
            - TLS 1.2 (0x0303)
        - extension_type: server_name (0x0000)
          length: 19 (0x0013)
          payload:
            length: 17 (0x0011)
            server_name_list:
            - name_type: host_name (0x00)
              hostname:
                length: 14 (0x000E)
                payload: api.github.com
```

# Raw
```
16 03 01 00 EE 01 00 00 EA 03 03 30 3E B7 F6 6F AC 63 01 FE 65 33 B1 B6 CC BC 63 63 67 46 17 6B EC 1A 47 2B B3 8C BE FC 84 AD 11 20 3E 80 EA AB 85 9A D5 3C 6B FA 3A B3 41 41 67 41 F1 0C 5F 5F CE 12 67 05 D5 F3 B4 91 C3 ED 73 06 00 14 13 02 13 01 13 03 C0 2C C0 2B CC A9 C0 30 C0 2F CC A8 00 FF 01 00 00 8D 00 0D 00 16 00 14 06 03 05 03 04 03 08 07 08 06 08 05 08 04 06 01 05 01 04 01 00 0B 00 02 01 00 00 05 00 05 01 00 00 00 00 00 17 00 00 00 0A 00 08 00 06 00 1D 00 17 00 18 00 2D 00 02 01 01 00 33 00 26 00 24 00 1D 00 20 C9 95 87 67 E3 8D 0D 6E F9 5A 71 97 AE F7 95 23 6A 0E B3 4B 30 43 9B 93 BF AF 25 AB 75 EF 40 10 00 23 00 00 00 2B 00 05 04 03 04 03 03 00 00 00 13 00 11 00 00 0E 61 70 69 2E 67 69 74 68 75 62 2E 63 6F 6D
16 03 03 00 7A 02 00 00 76 03 03 1E 66 21 9C 6B E7 03 5E B7 B0 52 72 FE 17 70 1E 6E 83 57 50 FF 42 D1 9D EB A1 29 EF 43 4E 7C 07 20 3E 80 EA AB 85 9A D5 3C 6B FA 3A B3 41 41 67 41 F1 0C 5F 5F CE 12 67 05 D5 F3 B4 91 C3 ED 73 06 13 01 00 00 2E 00 2B 00 02 03 04 00 33 00 24 00 1D 00 20 BE 6D F2 DA CF 0D 2A 45 75 ED EA 27 A7 DE 51 49 8F B9 89 17 F0 59 4F A4 45 B0 98 8B 0B 5F 8E 56 14 03 03 00 01 01 17 03 03 00 1B AB FF 99 C3 CB CB 3F 87 D6 93 70 7E 34 CC A7 03 EC EF 0E A2 78 E7 47 B3 F6 AF 0E 17 03 03 0C 51 C1 07 9B B1 E5 E0 7C E1 30 1F AE A6 B9 33 5E CC 20 E5 C3 1D DD E4 5D 98 DF 9A CE C7 23 49 18 2B 21 75 17 5C BE CF E5 FC EA 2E FC 10 21 D7 CF C9 D3 B4 3B EE F1 F2 F7 16 8B 1F DA 63 DD 37 25 02 C3 79 90 F2 C2 CE 1D 8B F9 F8 91 25 E2 54 1B ED EB 8E 91 44 4F 37 B2 0B 65 65 D8 75 E0 D4 B0 A4 02 7B 3B BA BA 6F B4 30 24 82 EE 23 5B 22 5D B7 46 4E C6 25 4F 83 ED 13 17 1A 9A 76 05 A9 E6 4A CB 98 41 B4 17 42 B1 C4 08 A2 5D 45 D5 B3 82 B2 7F CB 24 94 0A 1E 77 D5 C0 6B 07 4A 81 B9 F2 4D 5E DE 29 C1 A4 9B F1 6C EB 08 BF 5B 5F 76 F2 2C FA 8A DD 5F 6F 28 3A 20 9D A1 57 98 A2 10 BC 5B DF 78 69 D7 08 EF BC BD 2D ED 61 B9 D2 10 75 FC 17 1B 4B F4 A9 38 62 E5 43 C5 14 4F 97 6E EF 16 0E 7D 3A 9E 08 DB 6D 26 1C AA DF 02 C8 97 92 03 15 B1 34 FC D4 1A 9F 7C 5C C3 03 9D 15 58 DD 05 C8 A2 AC 51 AE 04 DB 0F F2 93 72 C7 76 3D A2 FF 50 8A 04 75 A1 07 4C 73 74 E1 58 53 91 EF 1C B0 D5 F4 A0 76 09 3C DF 49 7E 98 14 E7 74 02 F6 3A 40 58 46 08 26 5F 9A 39 A4 03 24 F5 BD 24 71 AE AE 49 61 B0 C9 94 FA 36 52 3B 3B DD 7A 38 59 33 90 08 1F 67 FF EC A2 73 16 2C EA 83 7F B4 03 09 10 4E B2 A2 0B 99 E9 99 32 0B 6C FD 3B 18 D3 30 60 98 21 1D 23 4F 47 89 AF CB F5 D2 63 79 8B 66 36 ED AC D7 17 EA AE 95 B6 4E 9B 80 15 FE 28 FB 55 D1 79 11 31 B4 67 DD 36 83 3A E4 96 B7 AF 76 43 EB 7A FF 55 62 DF D4 EF 9B 95 CA 2B 14 D4 B6 65 FF 49 08 E9 48 08 EF 17 72 07 51 6E 04 6D 12 81 99 61 C4 9F F7 E9 CA 40 4F 62 CA C1 64 21 52 85 13 29 37 31 25 9D 68 B1 F6 4E A5 B4 51 40 83 6B DF 50 4D 0C 1A 79 CF E5 12 17 89 DF 2A D2 07 2E 24 21 AB 13 52 23 14 F9 F5 9B B7 07 11 52 CB CD B0 27 8C D5 88 63 E2 DA 83 24 FB B5 D2 0E AB 2B D1 14 25 23 E0 F6 D4 46 1C E2 58 E7 76 D2 91 5A B4 19 A8 6D 7E 88 CC 3F 85 9A 94 57 5C 80 C8 6C D1 68 65 3C 7B BA C7 79 8B E4 CC 14 59 CA 32 59 69 05 F8 9D 9B DF 47 6E 80 9B 07 D1 EC B9 C0 A8 DB DE 4C B5 01 C8 22 0F 3A 27 AB 47 E6 56 B2 99 19 68 80 62 9F 47 99 D0 98 AE A9 E0 17 81 2B B6 59 E8 2A 7F BC 47 96 DB 7C 14 E5 5E 99 5F FD 78 BC 05 10 12 A4 11 12 A4 86 CF 97 12 C2 A3 49 12 27 D4 AE 60 8E 5C 21 A4 CA 5B C0 0E E3 AA 4F D2 16 9B AC 35 D6 F7 65 5C 18 4F 05 B4 4D C4 72 C1 55 65 FD DF 7B 44 D6 C4 DA C4 C8 CF B4 E5 DF E0 E6 2F D9 A3 19 E3 B9 1A DE 51 E7 EB 52 B6 BF 75 77 4B 86 7C 50 B4 B1 00 44 40 18 B9 14 DD 7A 96 E0 9B 14 48 B3 9C 03 54 3B 1F A5 DA 07 47 FB 27 A7 D6 93 FE 7B D9 27 B5 23 9D 43 E1 AF DD AC DC BA 7F 0E 97 F5 C0 44 4D 53 74 63 D1 15 D1 9B 0A 4C D9 5A AD 98 6C 76 28 D4 16 6E 51 CF A0 79 C6 93 62 39 27 88 DC 3A DC DC 2C D4 DA 74 FD C7 33 2F 64 90 3C BD C2 A1 3B 66 C8 A3 C4 07 A2 09 F3 3E AD E5 57 E0 E0 D2 35 21 FB A5 0B 2E 95 99 BE F6 ED 83 C2 26 C4 0D 5A 01 FA C5 12 22 A4 A5 75 C5 7B 16 75 3A 04 25 A6 45 29 AB 41 EF 82 B6 28 59 88 4B 5E D4 B9 EA 3D B0 37 15 A5 0F 58 A4 B2 01 92 94 F2 88 7A F3 02 D6 2A 25 AC 88 A0 DC 4E 01 4F 2A D8 E6 8F 03 8F F4 E4 A4 A6 58 CA 14 48 88 9C 63 2C E0 66 C1 A9 9F 29 8E 55 B8 9B EA 49 3D AC C8 24 EE 56 56 2B 98 47 E4 7F 1B 56 1B 97 13 92 80 53 6D 30 55 D2 17 6C 83 1A 99 62 45 2B 3E AC 59 74 A4 C5 41 EB F5 68 41 F0 2D 9A 40 97 73 D6 0E DA E9 24 4F 48 77 0A 7F 34 AD 3C 64 80 71 39 6D 0C 28 09 E8 4B C4 2C 3F 81 78 01 BD 87 EF 0F 16 D0 19 8A 33 D0 B7 3A B4 1E 7A E7 A2 27 49 F4 68 24 EC CB 11 23 B5 19 64 C3 A4 24 2D 74 E2 F0 95 75 ED 13 D7 90 C5 0C 0E 89 06 E2 4A 98 96 9F C7 CD 32 AA AB 92 BD C2 D0 A3 FC 08 98 79 F8 51 B2 C9 64 8C 94 F2 16 8A DE CC EC E3 72 4F F6 CF A7 FB 47 DF 0E 63 74 A0 86 2E A1 B1 F9 0B 2C 5A 5A B2 0C B8 36 51 21 AF 64 53 FA 8C 75 4C 3D C6 CE 71 47 2B 91 25 7A BF 8F CF 75 7E 03 AA 77 29 AE A4 B6 49 7E B6 69 75 90 98 54 D0 04 DF CC 0D 74 D2 B2 02 32 47 1C 47 D5 73 75 46 8C B2 A1 33 0E 9D 16 4A 8C 8C 96 C7 74 DD 8B 31 A1 BA 15 68 02 E5 AF CF 60 4A 31 67 5E 0B 16 A9 3B A4 03 6B 5D 1C 38 49 82 0D 10 3A 52 6F 48 66 76 E1 A7 C8 5E 42 52 1A 0D 33 95 B3 7C BE FB AC 70 39 2B DB 34 35 F6 D0 59 04 E5 8B 19 99 86 4E F6 66 0B BB 3F 7C 4B 12 11 77 B8 E9 48 72 09 F0 FF 62 C6 29 E1 F2 38 0B 1F FD A2 6C C4 5D BA 9D 41 B2 96 32 7C 57 46 AF 72 06 04 3A 19 BD 47 66 77 29 08 42 BF AA A7 4B DA 75 B0 4E FF E3 19 2E 9F CE 8B E3 A0 58 A1 B1 5B 55 3C 6A DB 05 65 F6 30 C8 2A 7F E0 DC 09 1B 90 89 BF 3C E9 C7 49 48 B4 52 8B B7 97 6D B6 25 34 5E AF 94 AF 57 A0 D9 F3 EA 26 4E 64 54 B8 1D 48 43 0B B0 D0 63 B8 25 51 6D 15 63 1B 5D E7 4D F6 5F 2F 16 A5 A8 82 2E 88 92 6F 0B F2 34 05 1D E7 E1 DA 9F AE 1C 3D 14 40 5A 7B 3C 5F 87 51 BB 89 73 4D 3D F6 07 BD 71 ED E5 15 73 64 3F 73 2A A0 A8 9F 35 47 7B 78 D7 48 57 E7 E3 05 1B E9 D0 26 09 5F 72 A2 7B 7E 1C CF 94 A7 C5 E9 1C 57 A1 0C 13 D6 CE 19 40 7E 0A C4 63 9C 9A 4A 73 0F BD CB A9 96 E6 06 43 EC D0 1C 92 FF 11 FA 03 7C B1 38 8E 0C B8 DE AE AB C1 46 EB B2 0B 32 DD AD 11 11 6F C3 95 89 17 57 7B C2 79 3D 90 E5 B4 00 15 13 E4 21 29 39 41 7D 34 78 66 6C 25 80 1A 9E 04 30 1A 9B E5 24 33 74 AE 5A D3 FD 8F 2D DA AA 93 1D 12 8C 06 C0 DA 42 77 F8 A7 A3 AF 0E B6 9D 6E 13 46 30 9E 2B EB 8F 98 73 6D 9B 2D EE B9 AC D6 3A 4B BA 66 0E 37 0F ED DA FC 83 31 C1 6B 07 83 A1 1D 0E 16 33 91 90 94 4B 42 D8 BC 54 3C A3 E7 61 59 40 50 D7 15 73 7B B5 97 E1 AF D3 B5 9C 4E 18 38 D8 EA 8B 31 4B 8C 7B 18 E8 CB 4E 5D D6 D9 DC 80 8E A6 F6 74 3C 39 D9 64 1F DF E5 25 6D 1C 9A AC 50 CB C7 C2 B3 D9 E5 02 72 71 FC 9F 3D 05 EF E1 EE F4 69 EC 4A EF 7C A2 6C B4 77 B7 50 AE A5 63 DA 10 ED 8C 9C A0 79 2F B9 9D 01 ED D9 5A A3 51 60 DC 41 FE 83 32 1D FB 22 4A 41 0F 01 DA 89 56 CE B3 4D A5 8E 65 DF BE A7 98 17 AF AE 72 01 C7 AC 6B F2 D6 48 94 60 C1 D1 EE E1 ED 2F 6C BA 9E DE 97 EF 6F FE 36 BC F8 3B 06 9A C9 6A 00 54 7A ED 60 F8 C8 EB B1 5E F0 38 92 7D E9 41 CA 3E F9 1A 26 02 A3 93 12 27 65 EA B7 BC 2F 20 68 89 D2 54 54 05 B3 C0 8C CE 3E 39 C6 29 B7 48 9E 43 D2 76 90 C9 1B CA 03 7B 46 3F C3 AC 57 06 B8 9D E2 2A 4F D2 24 CE F5 88 AA 27 BF 02 2C CA 3E 98 8D 59 35 BF 11 3C 8C 52 6D 96 10 C1 F8 14 CB D0 DF 75 71 14 8B 48 74 C8 85 8B 8D 43 3F 73 90 61 26 0E 20 FA CE 69 2D 29 36 11 FE 4D CD A2 6D 50 68 3C 63 53 C3 48 2B 89 FD 05 50 2A 80 41 D4 DE FE C7 FB 91 C5 B9 78 DC BE F9 97 C0 0B 3F 3B F3 68 CB 9E 24 B8 29 13 A3 05 2C 39 6F AE 77 02 EA A2 96 2A D3 EE F2 FF 44 B7 32 A8 1B A5 09 26 F8 65 7F 20 17 4C 3F 47 95 3A 7C 7C 98 11 AF A8 12 9C C3 89 90 64 38 AE 2E 67 41 C4 7D 66 50 12 9D 1E B5 F2 C0 C8 1B AB 90 8B F4 2E 07 96 6E 38 23 2A 66 D0 83 BD 3E 4E 53 63 4D 98 8D 1B 7E 74 3D 05 CA 29 90 B2 50 3A 6D F4 95 AD 26 EA E0 CE D5 D1 A3 7D 2E C1 AE C6 81 1A 61 E6 91 60 3E 60 48 02 DE F3 93 D9 F6 C9 3B EE 98 9F AB 82 CC E8 E5 78 EB BA 89 A7 18 F4 D5 95 E5 E9 90 91 29 BE 31 C0 0C FF B7 DB B3 AB A3 F3 5D 5F 43 06 B2 5C D4 1B BB 4D 74 50 1D B0 8D 66 29 9B F3 EB 6F A4 9A 57 7C 99 1E FC 4D E0 84 C0 E4 BB 5D E7 79 B8 F1 B4 B5 01 60 39 4F 27 61 FE 99 63 90 9E 55 FA BF 12 7E 47 FE D3 0D 29 94 93 4E D2 BC C8 B7 BC 88 D6 FA CD 2F F3 16 49 95 B7 1C 7A 59 65 6F D1 02 E1 65 83 C8 DB 5B EC 0C 5C 30 4D 39 FB 29 1A 6B F2 A7 DA D9 2C 5D 7D 06 5F F5 20 21 2B 95 73 03 F6 FB E9 3F 9C 41 87 8F 16 95 1E 6D C4 3A 42 30 F5 4D E9 4D 66 A5 12 08 68 6E 43 CC 4B 2F 8C 0D DC 98 27 34 8E 19 CA 51 4C 20 D3 DC 23 1E 9C F9 AB C3 68 92 62 B8 79 F9 46 35 DF EE 5E 90 3C 99 27 E7 E2 CB F9 B8 A9 E8 FA FE A5 4B 90 33 2B 21 49 29 F6 3A CC 47 94 E2 B5 68 AE 0D 98 D4 19 C8 8A 81 BA 50 19 A3 F9 65 B6 44 9D 54 8D 91 A7 30 A4 47 FF 48 55 B1 AF F6 FB 12 EB FF CD 98 49 75 A6 1B F1 FA 6C 4B 93 E2 92 B3 21 13 3C 2F 15 BE 0A BF E1 C6 73 4A E7 66 38 7C C4 C0 4B 2F B9 4B 27 ED 85 8C 17 3F 97 6A EE 8A 56 81 1C 09 6C 89 4D 01 C7 92 0A 9B 2E C8 20 6C 81 8D 27 7B 5A 59 B4 F1 EA CA 0B B0 BB 07 E7 2B 80 2B F1 70 B0 D0 F6 8C 88 D8 E6 2A C2 F7 CC 2B 9D 47 C1 C2 A9 94 B9 F1 3C E6 FA 62 5B CE 16 D8 DC FE EA F4 28 E3 E5 38 16 54 19 00 28 43 EA A7 AD 60 EF 7F EA 28 F0 91 D6 DD 7E 7A 0D 6D 9F 3F 61 C6 E4 7B 8C 80 BC E1 2A 53 9C FA B2 A6 3C B2 DE 55 E6 8D 60 33 66 F6 E5 C6 23 11 F4 34 3C 6D 48 80 DB 2B DA CA 94 99 FD 4F 73 91 D1 D2 98 4B A7 17 C9 19 B0 F2 C0 B1 7F 51 F4 1D C8 51 85 B8 3F 4A 86 53 C0 0F 2A F0 F5 88 CA D2 36 7C 39 D5 4B EF C1 C8 91 13 8D 63 8E 60 6B 13 7B BB 0A 28 B0 51 7F E0 0E 67 10 8E 8B 5A AF 13 AE CC E1 05 29 D0 C2 DF C4 D9 3D 9E 49 85 52 3B FD 4D 92 51 99 C2 DA 58 62 EB AC 4A 0B 0F 7D 96 8A 45 CC FE 27 92 81 0C 24 7C 96 BD C5 A4 6A FF 5D EF 6D 25 B9 8D 40 79 9D F3 C2 B3 47 F2 2E C8 0B 7C A5 BC 3B 9D F5 F6 48 92 25 6E 4B 4B 62 96 DA 4C DD 97 3D 68 4A 91 62 40 12 3F 76 1C E2 2B 8F C6 18 67 7C 9B AA DD DA F4 15 FA B6 46 06 6B C2 E7 0C 0F 88 B5 B8 81 52 D9 88 43 8C FA 45 07 44 76 06 D3 5B E6 84 0D 01 A2 7C BC AB FC 7D 06 C9 88 11 32 98 8F C7 ED 57 59 6A DD 9A 79 79 26 FC 1E 50 15 13 EE 10 23 BA 02 03 95 94 B8 D6 F0 CF A5 74 0F ED 77 04 DE 73 A7 D1 3D 04 E5 BC E0 63 3B 50 17 08 3D 66 35 1D 69 28 A8 5B F2 37 D6 3D 1F 54 0E A4 70 5D 91 9F 3C 20 8D 13 A6 B5 57 88 92 66 B3 63 E0 84 DC B3 6B 35 F1 F9 71 C9 B1 F6 0A 75 61 92 37 95 D9 1B F2 6E 60 F3 87 D8 08 49 6B 3D 26 53 CE F5 04 62 97 5A AA 7C 62 F8 D2 E8 93 7E D4 FA 97 1F B1 D3 A7 9C EA FB 3E 01 77 47 C3 B6 1C 67 F8 52 D7 21 C8 12 67 F2 AC 15 95 74 4B 93 15 E7 3F 0D 38 3A CB BA 0E C9 CD 13 7F 06 3E 82 E6 B1 76 3C A8 E2 ED 30 2A FA B6 53 A1 BA 4C DB 87 0F 54 5A 39 11 CA 30 32 59 9D 72 39 E1 B2 68 7A 31 B1 46 3D 5E E5 67 68 9D 4A 0D 12 30 72 B5 93 37 0E DB 30 2E 5A A9 3E 03 A1 FA 09 66 EE 8E A4 07 38 C4 7D 6F FC 93 AE CF 8D 73 09 C5 8B F8 DD 37 C0 EA 69 66 F7 F5 41 9A 21 5E 85 BE 3C D4 23 AB BC F2 28 8F EC A5 20 31 E2 E8 3A BE 7D C3 1C D0 F6 84 76 A8 70 FE A0 B1 CC C1 07 08 6B 63 55 1A 15 5A 40 3F 39 AF F9 EB 8F FC 89 55 0B AA BF 9C 0F E7 D5 E6 62 80 E7 97 57 93 43 ED 5D 33 8C ED CB 38 B5 AC B6 A4 D0 F0 20 85 32 88 46 2E 73 3F F8 13 E0 8F 88 E5 32 9C C5 AE 15 71 E3 2C 29 2C 87 F2 AB 15 10 7A D6 E6 A9 45 D1 77 EE 56 17 03 03 00 5F E4 3B D8 BF C0 5A 0A AF D0 E9 C9 2B D8 E9 ED 57 10 EA 92 16 14 DB C6 01 B3 03 B5 7B CE B4 CB F7 0B D3 AB 8F 63 7C 93 F5 18 0C 2E B4 CA 3D 3D 45 4E BE 40 D5 A6 C9 CB 4D C7 68 EC 21 E2 BD FF 80 87 39 04 D2 04 8A 1E 3B CB 91 08 03 43 7A A8 86 BD FA 9E B4 64 F6 AD 78 3D 0B 24 A2 76 97 BE 17 03 03 00 35 4D 54 7E 05 F2 BD D1 E5 12 F3 98 F1 D1 E8 44 C7 95 5C 69 F9 E5 5E D3 11 B8 C2 66 D7 33 3C 4F 35 37 FB 4D 51 42 81 86 9F 8C 35 FC E5 A8 7D 6D 8C 72 F4 5A 38 CB
14 03 03 00 01 01
17 03 03 00 35 CB F2 5E 15 E6 BE 92 AE AA 4B 5C B1 6C 2D D9 E7 12 27 BB D1 6C 40 00 87 FB 9F B3 0D 86 27 F0 A4 78 1A BC 48 21 7E DF 0E FF 94 12 68 93 4B 1A C4 C9 E6 E6 79 0C
17 03 03 00 13 5E 04 6C 5F FD F0 70 DA C8 F8 19 6C F1 74 54 C7 68 72 D0
```