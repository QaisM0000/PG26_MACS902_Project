# Benchmark results

Run at 2026-11-23T18:47:45Z on loopback. 200 full handshakes per policy (mutual TLS, no resumption), median of 5 transfers of 100 MiB per policy.

| Policy | Group | ClientHello (bytes) | ServerHello (bytes) | Handshake median (ms) | Handshake p95 (ms) | Throughput (MiB/s) |
|---|---|---|---|---|---|---|
| classical | X25519 | 235 | 122 | 1.207 | 2.324 | 88.9 |
| pq-hybrid | X25519MLKEM768 | 1411 | 1210 | 1.651 | 2.877 | 106.5 |

Handshake time is measured by the client and includes the TCP connection. Throughput is set by AES-256-GCM and the disk, not by the key exchange, so differences between policies are noise.

| Signature scheme | Signature (bytes) | Sign median (µs) | Verify median (µs) |
|---|---|---|---|
| Ed25519 | 64 | 35 | 89 |
| RSA-PSS-SHA256 (3072-bit) | 384 | 1582 | 67 |
