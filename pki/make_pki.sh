#!/bin/bash
# Builds the project PKI with the OpenSSL command line:
#   ca/      Root CA (RSA-4096). Private key encrypted with AES-256; it never leaves this folder.
#   server/  Server identity + a copy of the CA certificate.
#   client/  Client identity + a copy of the CA certificate.
#   rogue/   A second, untrusted CA and client. Used only by the negative tests.
#
# Usage:   bash pki/make_pki.sh
# Options: KEYTYPE=rsa                      identity keys as RSA-3072 instead of Ed25519
#          SERVER_SAN="DNS:host,IP:1.2.3.4" extra names for a server on another machine
#          CA_PASS=...                      CA passphrase (otherwise you are asked for it)
set -euo pipefail
cd "$(dirname "$0")"

KEYTYPE="${KEYTYPE:-ed25519}"
SERVER_SAN="${SERVER_SAN:-DNS:localhost,IP:127.0.0.1}"
ORG="/C=AE/ST=Dubai/O=MACS902 Secure File Transfer"

if [ -z "${CA_PASS:-}" ]; then
    read -r -s -p "Choose a passphrase for the CA private key: " CA_PASS; echo
fi
export CA_PASS

rm -rf ca server client rogue
mkdir -m 700 ca server client rogue
umask 077                                   # every key file is created readable by its owner only

new_key() {                                 # new_key <file>
    if [ "$KEYTYPE" = "rsa" ]; then
        openssl genrsa -out "$1" 3072 2>/dev/null
    else
        openssl genpkey -algorithm ED25519 -out "$1"
    fi
}

issue() {                                   # issue <folder> <common name> <extensions>
    new_key "$1/$1.key"
    openssl req -new -key "$1/$1.key" -subj "$ORG/CN=$2" -out "$1/$1.csr"
    openssl x509 -req -in "$1/$1.csr" -CA ca/ca.crt -CAkey ca/ca.key -passin env:CA_PASS \
        -CAcreateserial -days 90 -sha256 -out "$1/$1.crt" -extfile <(printf "%b" "$3") 2>/dev/null
    rm -f "$1/$1.csr"
    cp ca/ca.crt "$1/ca.crt"
}

# 1. Root CA. basicConstraints and keyUsage are critical, as RFC 5280 requires of a CA.
openssl genrsa -aes256 -passout env:CA_PASS -out ca/ca.key 4096 2>/dev/null
openssl req -x509 -new -key ca/ca.key -passin env:CA_PASS -sha256 -days 365 -out ca/ca.crt \
    -subj "$ORG/CN=Project Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Server and client identities. Each key authenticates its owner in TLS (digitalSignature)
#    and signs manifests or receipts (nonRepudiation). extendedKeyUsage stops a client
#    certificate from being used as a server certificate, and the reverse.
LEAF="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n"
issue server "localhost"          "${LEAF}extendedKeyUsage=serverAuth\nsubjectAltName=${SERVER_SAN}\n"
issue client "AuthorizedClient01" "${LEAF}extendedKeyUsage=clientAuth\n"

# 3. Rogue material for the negative tests: a CA the server does not trust.
openssl genrsa -out rogue/ca.key 2048 2>/dev/null
openssl req -x509 -new -key rogue/ca.key -sha256 -days 30 -out rogue/ca.crt -subj "/O=Rogue/CN=Rogue CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
new_key rogue/client.key
openssl req -new -key rogue/client.key -subj "/O=Rogue/CN=Mallory" -out rogue/client.csr
openssl x509 -req -in rogue/client.csr -CA rogue/ca.crt -CAkey rogue/ca.key -CAcreateserial -days 30 -sha256 \
    -out rogue/client.crt -extfile <(printf "%b" "${LEAF}extendedKeyUsage=clientAuth\n") 2>/dev/null
rm -f rogue/client.csr

chmod 644 ca/ca.crt server/*.crt client/*.crt rogue/*.crt
rm -f ca/ca.srl rogue/ca.srl

echo "[+] PKI built with $KEYTYPE identity keys:"
openssl verify -CAfile ca/ca.crt server/server.crt client/client.crt
for cert in ca/ca.crt server/server.crt client/client.crt; do
    openssl x509 -in "$cert" -noout -subject -fingerprint -sha256 | sed 's/^/    /'
done
echo "[+] Keep pki/ca/ca.key off the server and out of the repository."
