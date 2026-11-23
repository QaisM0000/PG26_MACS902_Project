#!/usr/bin/env python3
"""Mutual-TLS file receiver.

For each connection the server:
  1. completes a TLS 1.3 handshake that demands a client certificate from the project CA;
  2. verifies the sender's signature over the manifest, using the public key taken from
     that same verified certificate;
  3. streams the file to disk while hashing it;
  4. keeps the file only if the hash matches the signed manifest, then stores the evidence
     and returns a signed receipt (proof of delivery).
"""
import argparse
import hashlib
import hmac
import os
import socket
import ssl

from cryptography import x509
from cryptography.exceptions import InvalidSignature

import sft_common as sft
import tls_policy


def parse_args():
    parser = argparse.ArgumentParser(description="Secure file transfer server (mutual TLS 1.3).")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="pki/server/server.crt")
    parser.add_argument("--key", default="pki/server/server.key")
    parser.add_argument("--ca", default="pki/server/ca.crt", help="CA that client certificates must chain to")
    parser.add_argument("--store", default="received_files", help="folder for accepted files")
    parser.add_argument("--evidence", default="evidence/server", help="folder for manifests and receipts")
    parser.add_argument("--policy", default="pq-hybrid", choices=sorted(tls_policy.POLICY_GROUP))
    return parser.parse_args()


def build_context(args):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    context.load_verify_locations(cafile=args.ca)
    context.verify_mode = ssl.CERT_REQUIRED     # mutual TLS: no client certificate, no session
    context.num_tickets = 0                     # no resumption: every transfer runs a fresh key exchange
    tls_policy.pin_group(context, args.policy)
    return context


def storage_path(store, manifest):
    """Where an accepted file is kept. An earlier transfer is never overwritten."""
    path = os.path.join(store, manifest["filename"])
    if os.path.exists(path):
        stem, extension = os.path.splitext(manifest["filename"])
        path = os.path.join(store, f"{stem}.{manifest['transfer_id'][:8]}{extension}")
    return path


def refuse(tls, reason):
    print(f"[!] Transfer refused: {reason}")
    sft.send_error(tls, reason)


def handle(tls, args, own_certificate, own_key, own_names):
    peer_certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    group = tls_policy.check_session(tls, args.policy)
    print(f"[✓] mTLS handshake complete. Client: {sft.subject(peer_certificate)}")
    print(f"[*] Session: {tls.version()}, {tls.cipher()[0]}, key exchange {group}")

    # READY. Tells the client that its certificate was accepted, before it reveals any file details.
    sft.send_message(tls, sft.encode({"type": "ready", "protocol": sft.PROTOCOL}))

    # OFFER. Nothing touches the disk until the signed manifest has passed every check.
    manifest_bytes, manifest_signature = sft.recv_message(tls)
    try:
        sft.verify(peer_certificate.public_key(), manifest_signature, sft.MANIFEST_LABEL, manifest_bytes)
        manifest = sft.decode(manifest_bytes)
        sft.check_manifest(manifest, peer_certificate, own_names, args.evidence)
    except InvalidSignature:
        return refuse(tls, "manifest signature is invalid")
    except (sft.Rejected, sft.ProtocolError) as problem:
        return refuse(tls, str(problem))
    print(f"[✓] Manifest signature valid ({sft.scheme(peer_certificate.public_key())}): "
          f"'{manifest['filename']}', {manifest['size']} bytes")
    sft.send_message(tls, sft.encode({"type": "proceed"}))

    # DATA. Stream to a temporary file and hash on the way in.
    partial = os.path.join(args.store, f".{manifest['transfer_id']}.part")
    digest, remaining = hashlib.sha256(), manifest["size"]
    try:
        with open(partial, "wb") as out:
            while remaining:
                chunk = tls.recv(min(sft.CHUNK, remaining))
                if not chunk:
                    raise sft.ProtocolError("connection closed before the file was complete")
                out.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        if not hmac.compare_digest(digest.hexdigest(), manifest["sha256"]):
            return refuse(tls, "file does not match the signed manifest")
        stored = storage_path(args.store, manifest)
        os.replace(partial, stored)
    finally:
        if os.path.exists(partial):
            os.remove(partial)

    # RESULT. Store the evidence first, then acknowledge with a signed receipt.
    receipt_bytes = sft.build_receipt(manifest_bytes, manifest, own_certificate)
    receipt_signature = sft.sign(own_key, sft.RECEIPT_LABEL, receipt_bytes)
    folder = sft.write_evidence(args.evidence, manifest["transfer_id"], manifest_bytes, manifest_signature,
                                peer_certificate, receipt_bytes, receipt_signature, own_certificate)
    sft.send_message(tls, receipt_bytes, receipt_signature)
    print(f"[✓] File verified and stored as {stored}")
    print(f"[*] Signed receipt sent. Evidence stored in {folder}")


def main():
    args = parse_args()
    tls_policy.activate(args.policy)
    os.makedirs(args.store, exist_ok=True)
    os.makedirs(args.evidence, exist_ok=True)

    own_certificate = sft.load_certificate(args.cert)
    own_key = sft.load_private_key(args.key)
    own_names = sft.certificate_names(own_certificate)
    context = build_context(args)

    with socket.create_server((args.host, args.port)) as listener:
        print(f"[*] Server {sft.subject(own_certificate)} listening on {args.host}:{args.port}")
        print(f"[*] Receipts are signed with {sft.scheme(own_key)}")
        while True:
            connection, address = listener.accept()
            print(f"\n[+] Connection from {address[0]}:{address[1]}")
            connection.settimeout(30)
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    handle(tls, args, own_certificate, own_key, own_names)
            except ssl.SSLError as problem:
                print(f"[!] TLS session refused: {problem.reason or problem}")
            except tls_policy.PolicyError as problem:
                print(f"[!] Session below policy, closed: {problem}")
            except (sft.ProtocolError, OSError) as problem:
                print(f"[!] Connection dropped: {problem}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
