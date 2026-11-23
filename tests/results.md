# Security test results

Run at 2026-11-23T19:56:10Z. Python 3.13.7, OpenSSL 3.5.2 5 Aug 2025, cryptography 49.0.0, identity keys Ed25519, policy pq-hybrid.

| ID | Test | Expected | Observed | Result |
|---|---|---|---|---|
| T1 | Round trip at three sizes | hashes equal; receipt and evidence verify on both sides | 1 KiB ok, 1 MiB ok, 32 MiB ok | PASS |
| T2 | Negotiated TLS parameters | TLSv1.3, TLS_AES_256_GCM_SHA384, X25519MLKEM768 | TLSv1.3, TLS_AES_256_GCM_SHA384, X25519MLKEM768 | PASS |
| T3 | Downgrade attempts (classical group, TLS 1.2) | both handshakes refused | X25519-only client: SSLV3_ALERT_HANDSHAKE_FAILURE; TLS 1.2 client: TLSV1_ALERT_PROTOCOL_VERSION | PASS |
| T4 | Client without a certificate | session refused | TLSV13_ALERT_CERTIFICATE_REQUIRED | PASS |
| T5 | Client certificate from an untrusted CA | session refused | TLSV1_ALERT_UNKNOWN_CA | PASS |
| T6 | File altered after signing | rejected; nothing stored; no receipt | server: file does not match the signed manifest; file kept: False; receipt issued: False | PASS |
| T7 | Manifest signed by another key | rejected before any file bytes are sent | server: manifest signature is invalid | PASS |
| T8 | Replayed and stale manifests | both rejected | replay: transfer_id has already been used (replay); one hour old: manifest timestamp is outside the freshness window | PASS |
| T9 | Wrong server name | client refuses the server certificate | Hostname mismatch, certificate is not valid for 'files.example.com'. | PASS |
| T10 | Tampered evidence, checked offline | offline verification fails in all three cases | manifest.json altered: detected, receipt.sig altered: detected, file altered: detected | PASS |

10/10 tests passed.

ClientHello 1673 bytes, ServerHello 1210 bytes (default client offering both hybrid and classical key shares).
