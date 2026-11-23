# Key management

| Key | Where it lives | Who can read it | Protection |
|---|---|---|---|
| CA private key | pki/ca/ca.key | Owner only | Encrypted with AES-256 under a passphrase |
| Server private key | pki/server/server.key | Owner only | File permissions |
| Client private key | pki/client/client.key | Owner only | File permissions |
| Certificates (.crt) | pki/ca, pki/server, pki/client | Everyone | Public by design |

- Each machine generates its own keys with pki/make_pki.sh. Keys never leave that machine.
- No private key is committed. The .gitignore file blocks pki/ca, pki/server, pki/client and every .key and .pem file.
- Identity certificates are valid for 90 days and the CA certificate for 365 days.
- Not done in this prototype: revocation, hardware-backed key storage, separate keys for TLS and for signing.

- checked on 23 November 2026 against the listing in docs/evidence/ismail_keys.png.
