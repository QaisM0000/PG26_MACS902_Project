"""Application protocol shared by client.py, server.py and verify_evidence.py.

It runs inside the mutual-TLS channel and adds what TLS alone cannot give: evidence that a
third party can check afterwards (non-repudiation of origin and of delivery).

    server -> client   READY     message({"type": "ready"}), sent once the client certificate is accepted
    client -> server   OFFER     message(manifest, signature over manifest)
    server -> client   DECISION  message({"type": "proceed"})  or  message({"type": "error", ...})
    client -> server   DATA      exactly manifest["size"] raw bytes
    server -> client   RESULT    message(receipt, signature over receipt)
                                 or message({"type": "error", ...})

A message is two frames: a JSON body and a signature (empty when the body is unsigned).
A frame is a 4-byte big-endian length followed by that many bytes.
Signatures are made over the exact bytes that are sent and stored, never over re-encoded data.
"""
import hashlib
import json
import os
import secrets
import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

PROTOCOL = "sft/1"
CHUNK = 64 * 1024                 # file bytes are streamed in 64 KiB pieces
MAX_FRAME = 64 * 1024             # manifests, receipts and signatures are small
MAX_FILE = 2 * 1024 ** 3          # 2 GiB cap for the prototype
MAX_SKEW = timedelta(minutes=5)   # how old or how far ahead a manifest timestamp may be

# Domain-separation labels. The identity key also signs inside the TLS handshake, so every
# application signature is bound to its purpose and cannot be replayed as something else.
MANIFEST_LABEL = b"MACS902-SFT-v1/manifest\x00"
RECEIPT_LABEL = b"MACS902-SFT-v1/receipt\x00"

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class ProtocolError(Exception):
    """The peer broke the framing or sent something that is not valid protocol data."""


class Rejected(Exception):
    """A manifest or receipt failed a security check. The message says which one."""


# ----------------------------------------------------------------------------- framing

def recv_exact(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            raise ProtocolError("connection closed early")
        data.extend(packet)
    return bytes(data)


def send_frame(sock, payload):
    if len(payload) > MAX_FRAME:
        raise ProtocolError("frame too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock):
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ProtocolError("frame too large")
    return recv_exact(sock, length)


def encode(fields):
    """Deterministic JSON encoding: sorted keys, no extra whitespace."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode(payload):
    try:
        fields = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("message is not valid JSON") from None
    if not isinstance(fields, dict):
        raise ProtocolError("message is not a JSON object")
    return fields


def send_message(sock, body, signature=b""):
    send_frame(sock, body)
    send_frame(sock, signature)


def recv_message(sock):
    """Returns (body bytes, signature bytes)."""
    body = recv_frame(sock)
    return body, recv_frame(sock)


def send_error(sock, reason):
    send_message(sock, encode({"type": "error", "reason": reason}))


# ----------------------------------------------------------------------------- hashing and time

def sha256_file(path):
    """Hash a file without loading it into memory. Returns (hex digest, size in bytes)."""
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(text):
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise Rejected("timestamp is not in the expected UTC format") from None


# ----------------------------------------------------------------------------- certificates and keys

def load_certificate(path):
    with open(path, "rb") as handle:
        return x509.load_pem_x509_certificate(handle.read())


def load_private_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def fingerprint(certificate):
    """SHA-256 fingerprint of the DER-encoded certificate, as lowercase hex."""
    return certificate.fingerprint(hashes.SHA256()).hex()


def subject(certificate):
    return certificate.subject.rfc4514_string()


def certificate_names(certificate):
    """DNS names and IP addresses the certificate is valid for (subjectAltName)."""
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    names = set(san.get_values_for_type(x509.DNSName))
    names.update(str(address) for address in san.get_values_for_type(x509.IPAddress))
    return names


def validity_window(certificate):
    """(not_before, not_after) as timezone-aware datetimes, on old and new cryptography versions."""
    if hasattr(certificate, "not_valid_before_utc"):
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    return (certificate.not_valid_before.replace(tzinfo=timezone.utc),
            certificate.not_valid_after.replace(tzinfo=timezone.utc))


# ----------------------------------------------------------------------------- signatures

def scheme(key):
    """Name of the signature scheme that goes with a private or public key."""
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA-PSS-SHA256 ({key.key_size}-bit)"
    raise Rejected("unsupported key type: the identity key must be Ed25519 or RSA")


def sign(private_key, label, payload):
    """Sign label + payload with the identity key. The scheme follows the key type."""
    message = label + payload
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(message)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(message, _PSS, hashes.SHA256())
    raise Rejected("unsupported key type: the identity key must be Ed25519 or RSA")


def verify(public_key, signature, label, payload):
    """Raise cryptography.exceptions.InvalidSignature unless the signature is valid."""
    message = label + payload
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, message)
    elif isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, message, _PSS, hashes.SHA256())
    else:
        raise Rejected("unsupported key type: the identity key must be Ed25519 or RSA")


# ----------------------------------------------------------------------------- manifest and receipt

def build_manifest(path, sender_certificate, recipient):
    """What the sender commits to: this file, from this identity, to this recipient, now."""
    digest, size = sha256_file(path)
    return encode({
        "protocol": PROTOCOL,
        "type": "manifest",
        "transfer_id": secrets.token_hex(16),
        "filename": os.path.basename(path),
        "size": size,
        "sha256": digest,
        "sender": subject(sender_certificate),
        "sender_cert_sha256": fingerprint(sender_certificate),
        "recipient": recipient,
        "created_utc": utc_now(),
    })


def _is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def check_manifest(manifest, peer_certificate, own_names, evidence_root):
    """Server-side checks on a manifest whose signature has already been verified."""
    if manifest.get("protocol") != PROTOCOL or manifest.get("type") != "manifest":
        raise Rejected("not an sft/1 manifest")
    if manifest.get("sender_cert_sha256") != fingerprint(peer_certificate):
        raise Rejected("manifest names a different certificate from the one that authenticated")
    if manifest.get("recipient") not in own_names:
        raise Rejected("manifest is addressed to a different recipient")

    size, digest = manifest.get("size"), manifest.get("sha256")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE:
        raise Rejected("file size is missing or over the limit")
    if not _is_hex(digest, 64):
        raise Rejected("file digest is not a SHA-256 value")

    name = manifest.get("filename")
    if not isinstance(name, str) or name != os.path.basename(name) or name in ("", ".", "..") or "\x00" in name:
        raise Rejected("filename is not a plain file name")

    if abs(datetime.now(timezone.utc) - parse_utc(manifest.get("created_utc"))) > MAX_SKEW:
        raise Rejected("manifest timestamp is outside the freshness window")

    transfer_id = manifest.get("transfer_id")
    if not _is_hex(transfer_id, 32):
        raise Rejected("transfer_id is not a 128-bit hex value")
    if os.path.exists(os.path.join(evidence_root, transfer_id)):
        raise Rejected("transfer_id has already been used (replay)")


def build_receipt(manifest_bytes, manifest, receiver_certificate):
    """What the receiver commits to: it holds a file with this hash, for this exact manifest."""
    return encode({
        "protocol": PROTOCOL,
        "type": "receipt",
        "status": "accepted",
        "transfer_id": manifest["transfer_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "file_sha256": manifest["sha256"],
        "size": manifest["size"],
        "receiver": subject(receiver_certificate),
        "receiver_cert_sha256": fingerprint(receiver_certificate),
        "received_utc": utc_now(),
    })


def check_receipt(receipt, manifest_bytes, manifest, receiver_certificate):
    """Checks on a receipt whose signature has already been verified."""
    expected = {
        "protocol": PROTOCOL,
        "type": "receipt",
        "status": "accepted",
        "transfer_id": manifest["transfer_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "file_sha256": manifest["sha256"],
        "size": manifest["size"],
        "receiver_cert_sha256": fingerprint(receiver_certificate),
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise Rejected(f"receipt field '{field}' does not match the transfer")
    parse_utc(receipt.get("received_utc"))


# ----------------------------------------------------------------------------- evidence

EVIDENCE_FILES = ("manifest.json", "manifest.sig", "sender_cert.pem",
                  "receipt.json", "receipt.sig", "receiver_cert.pem")


def write_evidence(root, transfer_id, manifest_bytes, manifest_signature, sender_certificate,
                   receipt_bytes, receipt_signature, receiver_certificate):
    """Store everything a third party needs to check the transfer later. Returns the folder."""
    folder = os.path.join(root, transfer_id)
    os.makedirs(folder, mode=0o700)
    pem = serialization.Encoding.PEM
    contents = (manifest_bytes, manifest_signature, sender_certificate.public_bytes(pem),
                receipt_bytes, receipt_signature, receiver_certificate.public_bytes(pem))
    for name, data in zip(EVIDENCE_FILES, contents):
        with open(os.path.join(folder, name), "wb") as handle:
            handle.write(data)
    return folder
