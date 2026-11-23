#!/usr/bin/env python3
"""TLS handshake probe used by the test suite and the benchmark.

The probe plays a client outside our control. It can offer classical groups only, TLS 1.2
only, no certificate, a certificate from an untrusted CA, or the wrong server name, and it
reports what the server did.

It also reads the key-exchange group from the ServerHello. Python before 3.15 has no public
call for that, so the probe uses the ssl module's private _msg_callback debugging hook.
The ServerHello travels in clear, so this is the same value Wireshark shows. Test code only:
client.py and server.py use public calls and nothing else.
"""
import argparse
import json
import os
import socket
import ssl
import statistics
import struct
import sys
import time

GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x001D: "X25519", 0x001E: "X448",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
}


def server_hello_group(message):
    """Name of the group in the key_share extension of a ServerHello handshake message."""
    position = 4 + 2 + 32                               # handshake header, legacy_version, random
    position += 1 + message[position]                   # legacy_session_id_echo
    position += 2 + 1                                   # cipher_suite, legacy_compression_method
    end = position + 2 + struct.unpack("!H", message[position:position + 2])[0]
    position += 2
    while position < end:
        extension, length = struct.unpack("!HH", message[position:position + 4])
        position += 4
        if extension == 51:                             # key_share
            code = struct.unpack("!H", message[position:position + 2])[0]
            return GROUP_NAMES.get(code, hex(code))
        position += length
    return None


def client_context(pki, cert="client", groups=None, max_version=None):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=os.path.join(pki, "client", "ca.crt"))
    if cert:
        context.load_cert_chain(os.path.join(pki, cert, "client.crt"), os.path.join(pki, cert, "client.key"))
    if groups:
        context.set_ecdh_curve(groups)                  # restrict the offer to one classical group
    if max_version:
        context.maximum_version = max_version
    return context


def handshake(port, pki, cert="client", groups=None, max_version=None, server_name="localhost",
              host="127.0.0.1", wait_for_verdict=False):
    """One connection attempt. Returns a dict: accepted, error, version, cipher, group, sizes, time."""
    context = client_context(str(pki), cert, groups, max_version)
    seen = {}

    def on_message(connection, direction, version, content_type, message_type, data):
        name = getattr(message_type, "name", "")
        if name == "CLIENT_HELLO" and direction == "write":
            seen.setdefault("client_hello_bytes", len(data))
        elif name == "SERVER_HELLO" and direction == "read":
            seen["server_hello_bytes"] = len(data)
            seen["group"] = server_hello_group(data)

    context._msg_callback = on_message
    result = {"accepted": False, "error": None}
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                result["handshake_ms"] = (time.perf_counter() - started) * 1000
                result.update(accepted=True, version=tls.version(), cipher=tls.cipher()[0])
                if wait_for_verdict:
                    # A TLS 1.3 server checks the client certificate after the client's side of the
                    # handshake has returned, so a refusal only shows up on the next read. An accepted
                    # client receives the server's READY message instead.
                    tls.settimeout(5)
                    if tls.recv(1) == b"":
                        result.update(accepted=False, error="closed by server")
    except ssl.SSLCertVerificationError as problem:
        result.update(accepted=False, error=problem.verify_message)
    except ssl.SSLError as problem:
        result.update(accepted=False, error=problem.reason or str(problem))
    except OSError as problem:
        result.update(accepted=False, error=str(problem))
    result.update(seen)
    return result


def main():
    """Benchmark mode: repeat full handshakes under one policy and print the figures as JSON."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)
    import tls_policy

    parser = argparse.ArgumentParser(description="Measure TLS handshakes against a running server.")
    parser.add_argument("--policy", default="pq-hybrid", choices=sorted(tls_policy.POLICY_GROUP))
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--pki", default=os.path.join(root, "pki"))
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    tls_policy.activate(args.policy)

    times, first = [], None
    for _ in range(args.count):
        outcome = handshake(args.port, args.pki)
        if not outcome["accepted"]:
            sys.exit(f"handshake refused: {outcome['error']}")
        times.append(outcome["handshake_ms"])
        first = first or outcome
    times.sort()
    print(json.dumps({
        "policy": args.policy, "group": first["group"], "version": first["version"], "cipher": first["cipher"],
        "client_hello_bytes": first["client_hello_bytes"], "server_hello_bytes": first["server_hello_bytes"],
        "handshakes": args.count, "median_ms": round(statistics.median(times), 3),
        "p95_ms": round(times[int(len(times) * 0.95) - 1], 3),
    }))


if __name__ == "__main__":
    main()
