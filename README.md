# Secure File Transfer with Mutual TLS, Signed Evidence and Hybrid Post-Quantum Key Exchange

MACS 902 Modern Cryptography, group project.
This is a teaching prototype. See "Security notes and limits" before relying on it.

## What it does

| Property | Mechanism |
|---|---|
| Confidentiality | TLS 1.3 with AES-256-GCM. Key exchange is the hybrid group X25519MLKEM768 (X25519 + ML-KEM-768), so recorded traffic stays protected against a future quantum computer |
| Integrity | AEAD records in transit; SHA-256 of the file checked against the signed manifest before the file is kept |
| Authentication | Mutual TLS: both sides present X.509 certificates issued by the project CA |
| Non-repudiation of origin | The sender signs a manifest (file hash, name, size, sender, recipient, time, transfer ID) |
| Non-repudiation of delivery | The receiver returns a signed receipt over the manifest hash and file hash |

Both parties keep an evidence folder for every transfer. Anyone holding that folder and the CA
certificate can verify it offline with `verify_evidence.py`.

## Requirements

- Linux (built and tested on Kali), Python 3.10 or later
- OpenSSL 3.5 or later for the hybrid group. Check the version Python uses:
  `python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`
- `python3-cryptography` 40 or later: `sudo apt install python3-cryptography`

## Quick start

```bash
bash pki/make_pki.sh                       # once: CA, server identity, client identity
python3 server.py                       # terminal 1
python3 client.py sample_secret.txt     # terminal 2 (any file)
python3 verify_evidence.py evidence/client/<transfer_id> --file sample_secret.txt
```

`python3 server.py --help` and `python3 client.py --help` list every option
(port, host, certificate paths, storage folders, policy).

## TLS policy

The protocol version, key-exchange group and cipher suite are set in an OpenSSL configuration
file, not in Python. `tls_policy.py` loads the file, checks that OpenSSL applied it and refuses
to start otherwise.

| Policy | File | Key exchange | Use |
|---|---|---|---|
| `pq-hybrid` (default) | `tls-policy/pq-hybrid.cnf` | X25519MLKEM768 only | Normal operation |
| `classical` | `tls-policy/classical.cnf` | X25519 only | Benchmark baseline; fallback on OpenSSL older than 3.5 |

Both ends must use the same policy: `python3 server.py --policy classical` and
`python3 client.py <file> --policy classical`.

## Tests and measurements

```bash
python3 tests/run_tests.py      # ten checks, writes tests/results.md
python3 tests/bench.py          # handshake, throughput and signature figures, writes tests/bench_results.md
```

| ID | Test | Property defended |
|---|---|---|
| T1 | Round trip at three sizes; evidence verifies on both sides | All four |
| T2 | Session is TLS 1.3, AES-256-GCM, X25519MLKEM768 | Confidentiality |
| T3 | Classical-only client and TLS 1.2 client are refused | Confidentiality (downgrade) |
| T4 | Client without a certificate is refused | Authentication |
| T5 | Client certificate from an untrusted CA is refused | Authentication |
| T6 | File altered after signing is rejected, nothing stored, no receipt | Integrity |
| T7 | Manifest signed by another key is rejected | Origin |
| T8 | Replayed and stale manifests are rejected | Origin (freshness) |
| T9 | Client refuses a server whose certificate does not match the name | Authentication |
| T10 | Altered manifest, receipt or file fails offline verification | Non-repudiation |

## Evidence folder

`evidence/<side>/<transfer_id>/` holds six files: `manifest.json`, `manifest.sig`,
`sender_cert.pem`, `receipt.json`, `receipt.sig`, `receiver_cert.pem`.

## Repository layout

```
server.py            receiver: verifies the manifest, stores file and evidence, signs the receipt
client.py            sender: signs the manifest, sends the file, verifies the receipt
verify_evidence.py   offline check of an evidence folder
sft_common.py        application protocol: framing, manifest, receipt, signatures
tls_policy.py        loads and enforces the TLS policy file
tls-policy/          pq-hybrid.cnf, classical.cnf
pki/make_pki.sh      builds the CA and the identities
tests/               run_tests.py, bench.py, tls_probe.py, results
```

## Security notes and limits

- Authentication and the evidence signatures are classical (Ed25519 by default, RSA-PSS supported).
  Only the key exchange is post-quantum. Evidence that must outlive a quantum computer needs
  ML-DSA signatures or trusted timestamps.
- One identity key per party is used for TLS authentication and for signing. Signatures carry a
  purpose label to keep the two uses apart; production systems would use separate keys.
- Any certificate from the project CA is authorised. There is no revocation (CRL or OCSP).
- The receiver can accept a file and withhold the receipt. Fair exchange needs a trusted third party.
- Files are stored in plaintext after transfer. Identity keys are unencrypted on disk; the CA key is
  encrypted with a passphrase.
- The server handles one connection at a time.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `... has no hybrid ML-KEM groups` | Python is linked to OpenSSL older than 3.5 | Upgrade, or run both ends with `--policy classical` |
| `TLS session refused: SSLV3_ALERT_HANDSHAKE_FAILURE` (server shows `NO_SUITABLE_KEY_SHARE`) | Client and server run different policies | Use the same `--policy` on both |
| `TLSV13_ALERT_CERTIFICATE_REQUIRED` | Client sent no certificate | Check `--cert` and `--key` |
| `TLSV1_ALERT_UNKNOWN_CA` or `certificate verify failed` | Certificate is not from the project CA, or the PKI was rebuilt on one side only | Rerun `bash pki/make_pki.sh` and redistribute `pki/server` and `pki/client` |
| `Server certificate rejected: Hostname mismatch` | `--host` is not a name in the server certificate | Rebuild with `SERVER_SAN="DNS:<name>,IP:<address>" bash pki/make_pki.sh` |
| `Connection failed: [Errno 111] Connection refused` | Server not running, or wrong port | Start `server.py`; check `--port` |
| `[Errno 98] Address already in use` | An earlier server still holds the port | `pkill -f server.py`, or choose another `--port` |
| `manifest timestamp is outside the freshness window` | Clocks differ by more than five minutes | Synchronise the clocks |
| `No module named 'cryptography'` | Library missing | `sudo apt install python3-cryptography` |
| Wireshark shows no packets | Capturing on the wrong interface | Capture on `lo` with filter `tcp.port == 8443` |

## Team

| Member | Area |
|---|---|
| Qaisar Shaikh | Application protocol, client and server integration, evidence verifier |
| Mohammed Ismail | PKI, TLS policy files, server deployment and hardening |
| Jacob Gutz | Test suite runs, packet captures, benchmark, documentation |
