#!/usr/bin/env python3
"""Offline verification of one transfer's evidence folder.

Anyone who holds the folder and the project CA certificate can run this. It needs no
private key and no network connection, and it answers two questions:

  origin    did the named sender sign this exact file hash?
  delivery  did the named receiver acknowledge that same hash?
"""
import argparse
import os
import sys

from cryptography.exceptions import InvalidSignature

import sft_common as sft


def parse_args():
    parser = argparse.ArgumentParser(description="Verify a transfer's evidence offline.")
    parser.add_argument("folder", help="evidence folder, e.g. evidence/server/<transfer_id>")
    parser.add_argument("--ca", default="pki/ca/ca.crt", help="project CA certificate")
    parser.add_argument("--file", help="the transferred file, to check it against the signed hash")
    return parser.parse_args()


def issued_by(certificate, ca_certificate):
    try:
        certificate.verify_directly_issued_by(ca_certificate)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def valid_at(certificate, moment):
    not_before, not_after = sft.validity_window(certificate)
    return not_before <= moment <= not_after


def signature_ok(certificate, signature, label, payload):
    try:
        sft.verify(certificate.public_key(), signature, label, payload)
        return True
    except (InvalidSignature, sft.Rejected):
        return False


def receipt_matches(receipt, manifest_bytes, manifest, receiver_certificate):
    try:
        sft.check_receipt(receipt, manifest_bytes, manifest, receiver_certificate)
        return True
    except (sft.Rejected, KeyError):
        return False


def main():
    args = parse_args()

    def read(name):
        with open(os.path.join(args.folder, name), "rb") as handle:
            return handle.read()

    try:
        ca = sft.load_certificate(args.ca)
        manifest_bytes, manifest_signature = read("manifest.json"), read("manifest.sig")
        receipt_bytes, receipt_signature = read("receipt.json"), read("receipt.sig")
        sender = sft.load_certificate(os.path.join(args.folder, "sender_cert.pem"))
        receiver = sft.load_certificate(os.path.join(args.folder, "receiver_cert.pem"))
        manifest, receipt = sft.decode(manifest_bytes), sft.decode(receipt_bytes)
        signed_at = sft.parse_utc(manifest.get("created_utc"))
        received_at = sft.parse_utc(receipt.get("received_utc"))
    except (OSError, ValueError, sft.ProtocolError, sft.Rejected) as problem:
        print(f"[FAIL] Evidence is incomplete or unreadable: {problem}")
        return 1

    checks = [
        ("Sender certificate is issued by the project CA", issued_by(sender, ca)),
        ("Sender certificate was valid when the manifest was signed", valid_at(sender, signed_at)),
        ("Manifest signature is valid under the sender certificate",
         signature_ok(sender, manifest_signature, sft.MANIFEST_LABEL, manifest_bytes)),
        ("Manifest names that same sender certificate",
         manifest.get("sender_cert_sha256") == sft.fingerprint(sender)),
        ("Receiver certificate is issued by the project CA", issued_by(receiver, ca)),
        ("Receiver certificate was valid when the receipt was signed", valid_at(receiver, received_at)),
        ("Receipt signature is valid under the receiver certificate",
         signature_ok(receiver, receipt_signature, sft.RECEIPT_LABEL, receipt_bytes)),
        ("Receipt refers to this manifest and this file hash",
         receipt_matches(receipt, manifest_bytes, manifest, receiver)),
    ]
    if args.file:
        try:
            matches = sft.sha256_file(args.file)[0] == manifest.get("sha256")
        except OSError:
            matches = False
        checks.append((f"File '{args.file}' matches the signed SHA-256", matches))

    for description, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {description}")

    if not all(passed for _, passed in checks):
        print("\nRESULT: evidence does NOT verify.")
        return 1
    print(f"\nRESULT: evidence verifies ({sft.scheme(sender.public_key())}).")
    print(f"  Origin:   {sft.subject(sender)} signed SHA-256 {manifest['sha256']}")
    print(f"            for file '{manifest['filename']}' ({manifest['size']} bytes) at {manifest['created_utc']}")
    print(f"  Delivery: {sft.subject(receiver)} acknowledged the same hash at {receipt['received_utc']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
