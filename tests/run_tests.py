#!/usr/bin/env python3
"""Security test suite for the secure file transfer prototype.

Starts a real server under the pq-hybrid policy, runs one positive test and nine attacks
or failure cases against it, prints a pass/fail table and writes tests/results.md.

Usage:  python3 tests/run_tests.py
"""
import os
import pathlib
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import cryptography          # noqa: E402
import sft_common as sft     # noqa: E402
import tls_probe             # noqa: E402

PORT = 9443
PKI = ROOT / "pki"
RUN = ROOT / "tests" / "_run"
state = {}                   # values that later tests reuse (transfer id, file paths, server process)


# ----------------------------------------------------------------------------- helpers

def start_server(policy="pq-hybrid"):
    log = RUN / f"server_{policy}.log"
    with open(log, "w") as output:
        process = subprocess.Popen(
            [sys.executable, "-u", "server.py", "--port", str(PORT), "--policy", policy,
             "--store", str(RUN / "received"), "--evidence", str(RUN / "evidence_server")],
            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    deadline = time.time() + 15
    while time.time() < deadline:
        if "listening on" in log.read_text():
            state["server"] = process
            return
        if process.poll() is not None:
            break
        time.sleep(0.1)
    process.kill()
    sys.exit(f"Server did not start. See {log}:\n{log.read_text()}")


def stop_server():
    process = state.pop("server", None)
    if process:
        process.terminate()
        process.wait(timeout=10)


def client(path, policy="pq-hybrid"):
    return subprocess.run(
        [sys.executable, "client.py", str(path), "--port", str(PORT), "--policy", policy,
         "--evidence", str(RUN / "evidence_client")],
        cwd=ROOT, capture_output=True, text=True, timeout=600)


def verify(folder, file=None):
    command = [sys.executable, "verify_evidence.py", str(folder), "--ca", str(PKI / "ca" / "ca.crt")]
    if file:
        command += ["--file", str(file)]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True).returncode


def offer(manifest_bytes, signature, body=None):
    """Speak the application protocol by hand, as an authenticated client that misbehaves."""
    context = tls_probe.client_context(str(PKI))
    with socket.create_connection(("127.0.0.1", PORT), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            sft.recv_message(tls)                               # READY
            sft.send_message(tls, manifest_bytes, signature)
            reply = sft.decode(sft.recv_message(tls)[0])
            if reply.get("type") != "proceed" or body is None:
                return reply
            tls.sendall(body)
            return sft.decode(sft.recv_message(tls)[0])


def flip_byte(path, position=None):
    data = bytearray(path.read_bytes())
    data[len(data) // 2 if position is None else position] ^= 0x01
    path.write_bytes(data)


# ----------------------------------------------------------------------------- tests
# Each test returns (expected, observed, passed).

def t1_round_trip():
    observed, all_ok = [], True
    for label, size in (("1 KiB", 1024), ("1 MiB", 1024 ** 2), ("32 MiB", 32 * 1024 ** 2)):
        source = RUN / "files" / f"sample_{size}.bin"
        source.write_bytes(os.urandom(size))
        before = set(os.listdir(RUN / "evidence_client"))
        done = client(source)
        new = set(os.listdir(RUN / "evidence_client")) - before
        ok = done.returncode == 0 and len(new) == 1
        if ok:
            transfer_id, stored = new.pop(), RUN / "received" / source.name
            ok = (sft.sha256_file(stored)[0] == sft.sha256_file(source)[0]
                  and verify(RUN / "evidence_client" / transfer_id, stored) == 0
                  and verify(RUN / "evidence_server" / transfer_id, source) == 0)
            state.update(transfer_id=transfer_id, source=source)
        observed.append(f"{label} {'ok' if ok else 'FAILED'}")
        all_ok = all_ok and ok
    return "hashes equal; receipt and evidence verify on both sides", ", ".join(observed), all_ok


def t2_negotiated_parameters():
    seen = tls_probe.handshake(PORT, PKI)
    got = (seen.get("version"), seen.get("cipher"), seen.get("group"))
    state["hello_sizes"] = (seen.get("client_hello_bytes"), seen.get("server_hello_bytes"))
    return ("TLSv1.3, TLS_AES_256_GCM_SHA384, X25519MLKEM768", ", ".join(map(str, got)),
            seen["accepted"] and got == ("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768"))


def t3_downgrade_refused():
    classical = tls_probe.handshake(PORT, PKI, groups="X25519")
    old_tls = tls_probe.handshake(PORT, PKI, max_version=ssl.TLSVersion.TLSv1_2)
    return ("both handshakes refused",
            f"X25519-only client: {classical['error']}; TLS 1.2 client: {old_tls['error']}",
            not classical["accepted"] and not old_tls["accepted"])


def t4_no_client_certificate():
    seen = tls_probe.handshake(PORT, PKI, cert=None, wait_for_verdict=True)
    return "session refused", str(seen["error"]), not seen["accepted"]


def t5_rogue_ca_certificate():
    seen = tls_probe.handshake(PORT, PKI, cert="rogue", wait_for_verdict=True)
    return "session refused", str(seen["error"]), not seen["accepted"]


def t6_file_altered_after_signing():
    source = RUN / "files" / "altered.bin"
    source.write_bytes(os.urandom(4096))
    manifest_bytes = sft.build_manifest(source, state["client_cert"], "localhost")
    signature = sft.sign(state["client_key"], sft.MANIFEST_LABEL, manifest_bytes)
    body = bytearray(source.read_bytes())
    body[-1] ^= 0x01
    reply = offer(manifest_bytes, signature, bytes(body))
    kept = (RUN / "received" / source.name).exists()
    receipt = (RUN / "evidence_server" / sft.decode(manifest_bytes)["transfer_id"]).exists()
    return ("rejected; nothing stored; no receipt",
            f"server: {reply.get('reason')}; file kept: {kept}; receipt issued: {receipt}",
            reply.get("type") == "error" and not kept and not receipt)


def t7_manifest_signed_by_another_key():
    source = RUN / "files" / "forged.bin"
    source.write_bytes(os.urandom(1024))
    manifest_bytes = sft.build_manifest(source, state["client_cert"], "localhost")
    rogue_key = sft.load_private_key(PKI / "rogue" / "client.key")
    reply = offer(manifest_bytes, sft.sign(rogue_key, sft.MANIFEST_LABEL, manifest_bytes))
    return "rejected before any file bytes are sent", f"server: {reply.get('reason')}", reply.get("type") == "error"


def t8_replayed_or_stale_manifest():
    folder = RUN / "evidence_client" / state["transfer_id"]
    replay = offer((folder / "manifest.json").read_bytes(), (folder / "manifest.sig").read_bytes())
    stale = sft.decode((folder / "manifest.json").read_bytes())
    stale["transfer_id"] = os.urandom(16).hex()
    stale["created_utc"] = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale_bytes = sft.encode(stale)
    old = offer(stale_bytes, sft.sign(state["client_key"], sft.MANIFEST_LABEL, stale_bytes))
    return ("both rejected", f"replay: {replay.get('reason')}; one hour old: {old.get('reason')}",
            replay.get("type") == "error" and old.get("type") == "error")


def t9_wrong_server_name():
    seen = tls_probe.handshake(PORT, PKI, server_name="files.example.com")
    return "client refuses the server certificate", str(seen["error"]), not seen["accepted"]


def t10_tampered_evidence():
    folder = RUN / "evidence_server" / state["transfer_id"]
    detected = {}
    for name in ("manifest.json", "receipt.sig"):
        copy = RUN / "tampered" / name.replace(".", "_")
        shutil.copytree(folder, copy)
        flip_byte(copy / name)
        detected[name] = verify(copy) != 0
    altered = RUN / "tampered" / "file.bin"
    shutil.copy(state["source"], altered)
    flip_byte(altered, 0)
    detected["file"] = verify(folder, altered) != 0
    return ("offline verification fails in all three cases",
            ", ".join(f"{name} altered: {'detected' if hit else 'MISSED'}" for name, hit in detected.items()),
            all(detected.values()))


TESTS = [
    ("T1", "Round trip at three sizes", t1_round_trip),
    ("T2", "Negotiated TLS parameters", t2_negotiated_parameters),
    ("T3", "Downgrade attempts (classical group, TLS 1.2)", t3_downgrade_refused),
    ("T4", "Client without a certificate", t4_no_client_certificate),
    ("T5", "Client certificate from an untrusted CA", t5_rogue_ca_certificate),
    ("T6", "File altered after signing", t6_file_altered_after_signing),
    ("T7", "Manifest signed by another key", t7_manifest_signed_by_another_key),
    ("T8", "Replayed and stale manifests", t8_replayed_or_stale_manifest),
    ("T9", "Wrong server name", t9_wrong_server_name),
    ("T10", "Tampered evidence, checked offline", t10_tampered_evidence),
]


def main():
    if "OPENSSL_CONF" in os.environ:
        sys.exit("Run the tests from a shell where OPENSSL_CONF is not set.")
    shutil.rmtree(RUN, ignore_errors=True)
    for folder in ("received", "evidence_server", "evidence_client", "files", "tampered"):
        (RUN / folder).mkdir(parents=True)
    state["client_cert"] = sft.load_certificate(PKI / "client" / "client.crt")
    state["client_key"] = sft.load_private_key(PKI / "client" / "client.key")

    environment = (f"Python {platform.python_version()}, {ssl.OPENSSL_VERSION}, cryptography "
                   f"{cryptography.__version__}, identity keys {sft.scheme(state['client_key'])}, policy pq-hybrid")
    print(environment + "\n")
    rows = []
    start_server()
    try:
        for test_id, name, function in TESTS:
            try:
                expected, observed, passed = function()
            except Exception as problem:                     # a crashed test is a failed test
                expected, observed, passed = "-", f"test crashed: {problem!r}", False
            rows.append((test_id, name, expected, observed, "PASS" if passed else "FAIL"))
            print(f"[{rows[-1][4]}] {test_id:<4}{name}\n         {observed}")
    finally:
        stop_server()

    passed = sum(row[4] == "PASS" for row in rows)
    print(f"\n{passed}/{len(rows)} tests passed.")
    lines = ["# Security test results\n", f"Run at {sft.utc_now()}. {environment}.\n",
             "| ID | Test | Expected | Observed | Result |", "|---|---|---|---|---|"]
    lines += [f"| {' | '.join(row)} |" for row in rows]
    lines.append(f"\n{passed}/{len(rows)} tests passed.")
    if all(state.get("hello_sizes", (None, None))):
        lines.append(f"\nClientHello {state['hello_sizes'][0]} bytes, ServerHello {state['hello_sizes'][1]} bytes "
                     "(default client offering both hybrid and classical key shares).")
    (ROOT / "tests" / "results.md").write_text("\n".join(lines) + "\n")
    print("Table written to tests/results.md")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
