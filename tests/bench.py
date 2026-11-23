#!/usr/bin/env python3
"""Measurements for the evaluation section of the report.

  1. Handshake cost of the hybrid group against the classical baseline (time and message sizes).
  2. Transfer throughput under each policy.
  3. The two supported signature schemes side by side.

Usage:  python3 tests/bench.py            (writes tests/bench_results.md)
"""
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

import run_tests as suite
import sft_common as sft

HANDSHAKES = 200
PAYLOAD_MIB = 100
TRANSFERS = 5
SIGNATURES = 200


def measure_policy(policy, payload):
    suite.start_server(policy)
    try:
        probe = subprocess.run(
            [sys.executable, str(suite.ROOT / "tests" / "tls_probe.py"), "--policy", policy,
             "--port", str(suite.PORT), "--count", str(HANDSHAKES)],
            capture_output=True, text=True, timeout=600)
        if probe.returncode != 0:
            sys.exit(f"Handshake probe failed under {policy}: {probe.stdout}{probe.stderr}")
        figures = json.loads(probe.stdout.strip().splitlines()[-1])
        rates = []
        for _ in range(TRANSFERS):
            sent = suite.client(payload, policy)
            rate = re.search(r"\(([\d.]+) MiB/s\)", sent.stdout)
            if sent.returncode != 0 or not rate:
                sys.exit(f"Transfer failed under {policy}: {sent.stdout}{sent.stderr}")
            rates.append(float(rate.group(1)))
        figures["throughput_mib_s"] = statistics.median(rates)
    finally:
        suite.stop_server()
    return figures


def measure_signatures():
    message = sft.MANIFEST_LABEL + os.urandom(400)             # about the size of a real manifest
    rows = []
    for key in (ed25519.Ed25519PrivateKey.generate(), rsa.generate_private_key(65537, 3072)):
        signature = sft.sign(key, b"", message)
        sign_times, verify_times = [], []
        for _ in range(SIGNATURES):
            started = time.perf_counter()
            sft.sign(key, b"", message)
            sign_times.append(time.perf_counter() - started)
            started = time.perf_counter()
            sft.verify(key.public_key(), signature, b"", message)
            verify_times.append(time.perf_counter() - started)
        rows.append((sft.scheme(key), len(signature), statistics.median(sign_times) * 1e6,
                     statistics.median(verify_times) * 1e6))
    return rows


def main():
    if "OPENSSL_CONF" in os.environ:
        sys.exit("Run the benchmark from a shell where OPENSSL_CONF is not set.")
    shutil.rmtree(suite.RUN, ignore_errors=True)
    for folder in ("received", "evidence_server", "evidence_client", "files"):
        (suite.RUN / folder).mkdir(parents=True)
    payload = suite.RUN / "files" / f"payload_{PAYLOAD_MIB}MiB.bin"
    with open(payload, "wb") as handle:
        for _ in range(PAYLOAD_MIB):
            handle.write(os.urandom(1024 * 1024))

    results = [measure_policy(policy, payload) for policy in ("classical", "pq-hybrid")]
    lines = ["# Benchmark results\n",
             f"Run at {sft.utc_now()} on loopback. {HANDSHAKES} full handshakes per policy (mutual TLS, no "
             f"resumption), median of {TRANSFERS} transfers of {PAYLOAD_MIB} MiB per policy.\n",
             "| Policy | Group | ClientHello (bytes) | ServerHello (bytes) | Handshake median (ms) | "
             "Handshake p95 (ms) | Throughput (MiB/s) |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['policy']} | {r['group']} | {r['client_hello_bytes']} | {r['server_hello_bytes']} | "
                     f"{r['median_ms']} | {r['p95_ms']} | {r['throughput_mib_s']} |")
    lines += ["", "Handshake time is measured by the client and includes the TCP connection. Throughput is set by "
              "AES-256-GCM and the disk, not by the key exchange, so differences between policies are noise.", "",
              "| Signature scheme | Signature (bytes) | Sign median (µs) | Verify median (µs) |", "|---|---|---|---|"]
    for name, size, sign_us, verify_us in measure_signatures():
        lines.append(f"| {name} | {size} | {sign_us:.0f} | {verify_us:.0f} |")
    text = "\n".join(lines) + "\n"
    (suite.ROOT / "tests" / "bench_results.md").write_text(text)
    print(text + "\nWritten to tests/bench_results.md")


if __name__ == "__main__":
    main()
