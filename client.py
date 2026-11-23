#!/usr/bin/env python3
"""Mutual-TLS file sender.

The client authenticates the server and itself with X.509 certificates from the project CA,
signs a manifest that commits to the file's SHA-256 hash, sends the file, and accepts the
transfer as delivered only after verifying the server's signed receipt.
"""
import argparse
import os
import socket
import ssl
import sys
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature

import sft_common as sft
import tls_policy


def parse_args():
    parser = argparse.ArgumentParser(description="Secure file transfer client (mutual TLS 1.3).")
    parser.add_argument("file", help="path of the file to send")
    parser.add_argument("--host", default="localhost", help="server name; must match the server certificate")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="pki/client/client.crt")
    parser.add_argument("--key", default="pki/client/client.key")
    parser.add_argument("--ca", default="pki/client/ca.crt", help="CA that the server certificate must chain to")
    parser.add_argument("--evidence", default="evidence/client", help="folder for manifests and receipts")
    parser.add_argument("--policy", default="pq-hybrid", choices=sorted(tls_policy.POLICY_GROUP))
    return parser.parse_args()


def build_context(args):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)   # trusts the project CA only
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    tls_policy.pin_group(context, args.policy)
    return context


def transfer(tls, args, own_certificate, own_key):
    server_certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    group = tls_policy.check_session(tls, args.policy)

    # READY. A TLS 1.3 server checks the client certificate after the client's handshake has returned,
    # so a refusal arrives here. Nothing about the file is sent before the server has accepted us.
    if sft.decode(sft.recv_message(tls)[0]).get("type") != "ready":
        print("[!] Server did not confirm the session.")
        return 1
    print(f"[✓] Mutual authentication complete with {args.host}:{args.port}. "
          f"Server: {sft.subject(server_certificate)}")
    print(f"[*] Session: {tls.version()}, {tls.cipher()[0]}, key exchange {group}")

    # OFFER: a signed manifest that commits to the file hash, the sender and the recipient.
    manifest_bytes = sft.build_manifest(args.file, own_certificate, args.host)
    manifest = sft.decode(manifest_bytes)
    manifest_signature = sft.sign(own_key, sft.MANIFEST_LABEL, manifest_bytes)
    print(f"[*] Manifest for '{manifest['filename']}' ({manifest['size']} bytes) signed with {sft.scheme(own_key)}")
    sft.send_message(tls, manifest_bytes, manifest_signature)

    decision = sft.decode(sft.recv_message(tls)[0])
    if decision.get("type") != "proceed":
        print(f"[!] Server refused the transfer: {decision.get('reason', 'no reason given')}")
        return 1

    # DATA: stream the file in chunks.
    started = time.perf_counter()
    with open(args.file, "rb") as handle:
        while chunk := handle.read(sft.CHUNK):
            tls.sendall(chunk)

    # RESULT: delivery counts only if the receipt verifies under the server's certificate.
    receipt_bytes, receipt_signature = sft.recv_message(tls)
    elapsed = time.perf_counter() - started
    receipt = sft.decode(receipt_bytes)
    if receipt.get("type") != "receipt":
        print(f"[!] Server rejected the file: {receipt.get('reason', 'no reason given')}")
        return 1
    try:
        sft.verify(server_certificate.public_key(), receipt_signature, sft.RECEIPT_LABEL, receipt_bytes)
        sft.check_receipt(receipt, manifest_bytes, manifest, server_certificate)
    except InvalidSignature:
        print("[!] Receipt signature is invalid. Delivery is not proven.")
        return 1
    except sft.Rejected as problem:
        print(f"[!] Receipt rejected: {problem}")
        return 1

    folder = sft.write_evidence(args.evidence, manifest["transfer_id"], manifest_bytes, manifest_signature,
                                own_certificate, receipt_bytes, receipt_signature, server_certificate)
    megabytes = manifest["size"] / (1024 * 1024)
    print(f"[✓] Signed receipt verified: server acknowledged SHA-256 {manifest['sha256'][:16]}... "
          f"at {receipt['received_utc']}")
    print(f"[*] Sent {manifest['size']} bytes in {elapsed:.3f} s ({megabytes / max(elapsed, 1e-9):.1f} MiB/s)")
    print(f"[*] Evidence stored in {folder}")
    return 0


def main():
    args = parse_args()
    tls_policy.activate(args.policy)
    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        return 1

    own_certificate = sft.load_certificate(args.cert)
    own_key = sft.load_private_key(args.key)
    context = build_context(args)
    try:
        with socket.create_connection((args.host, args.port), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=args.host) as tls:
                return transfer(tls, args, own_certificate, own_key)
    except ssl.SSLCertVerificationError as problem:
        print(f"[!] Server certificate rejected: {problem.verify_message}")
    except ssl.SSLError as problem:
        print(f"[!] TLS session refused: {problem.reason or problem}")
    except tls_policy.PolicyError as problem:
        print(f"[!] Session below policy, closed: {problem}")
    except (sft.ProtocolError, OSError) as problem:
        print(f"[!] Connection failed: {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
