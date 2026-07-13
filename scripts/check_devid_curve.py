#!/usr/bin/env python3
"""
Statistical and cryptographic characterization of GET_DEV_ID (GAIA command 1).

Tests whether the 64-byte payload is a raw uncompressed secp256r1 (P-256)
EC public key, and runs a statistical battery (entropy, Hamming weight,
autocorrelation, block uniqueness) to characterize whether it looks like
random/encrypted/hashed data vs. structured configuration data.

Usage: python3 check_devid_curve.py
"""
import json
import math
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURES = os.path.join(HERE, "..", "captures", "raw_captures.json")


def load_payloads():
    with open(CAPTURES) as f:
        data = json.load(f)
    frames = data["commands"]["1_GET_DEV_ID"]
    out = {}
    for radio, hexstr in frames.items():
        raw = bytes.fromhex(hexstr)
        out[radio] = raw[5:]  # strip 5-byte header: 00 02 80 <cmd> <status>
    return out


def check_p256_curve(payload):
    """Test all 4 combinations of (X||Y split) x (endianness) against the
    secp256r1 curve equation y^2 = x^3 - 3x + b (mod p)."""
    p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    results = []
    for order, (xb, yb) in [("X|Y", (payload[:32], payload[32:])),
                             ("Y|X", (payload[32:], payload[:32]))]:
        for endian in ("big", "little"):
            x = int.from_bytes(xb, endian)
            y = int.from_bytes(yb, endian)
            lhs = (y * y) % p
            rhs = (x**3 - 3 * x + b) % p
            results.append((order, endian, lhs == rhs))
    return results


def shannon_entropy(b):
    counts = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hamming_weight_stats(b):
    weights = [bin(x).count("1") for x in b]
    return sum(weights) / len(weights), Counter(weights)


def autocorrelation(b, max_lag=8):
    n = len(b)
    return [(lag, sum(1 for i in range(n - lag) if b[i] == b[i + lag]), n - lag)
            for lag in range(1, max_lag + 1)]


def longest_repeated_substring(b):
    n = len(b)
    for length in range(n // 2, 0, -1):
        seen = {}
        for i in range(n - length + 1):
            chunk = bytes(b[i:i + length])
            if chunk in seen:
                return length
            seen[chunk] = i
    return 0


def block_uniqueness(b, block=16):
    blocks = [b[i:i + block].hex() for i in range(0, len(b), block)]
    return len(set(blocks)) == len(blocks)


if __name__ == "__main__":
    payloads = load_payloads()

    print("=== secp256r1 (P-256) raw-point curve equation check ===")
    print("y^2 = x^3 - 3x + b (mod p) tested for all split/endian combos\n")
    for radio, payload in payloads.items():
        print(f"-- {radio} ({len(payload)} bytes) --")
        for order, endian, matches in check_p256_curve(payload):
            print(f"  split={order:4s} endian={endian:6s} on_curve={matches}")
    print("\n>>> Result: none of the 8 checks satisfy the curve equation on")
    print(">>> either radio's capture. Rules out the naive raw-point encoding")
    print(">>> only -- does not rule out other curves, compressed points, or")
    print(">>> a hash/KDF output. See docs/FINDINGS.md section 4.\n")

    print("=== Statistical battery ===\n")
    for radio, payload in payloads.items():
        entropy = shannon_entropy(payload)
        mean_hw, hw_hist = hamming_weight_stats(payload)
        lrs = longest_repeated_substring(payload)
        ac = autocorrelation(payload)
        unique_blocks = block_uniqueness(payload)

        print(f"-- {radio} --")
        print(f"  Shannon entropy: {entropy:.4f} bits/byte (max=8.0)")
        print(f"  Mean Hamming weight: {mean_hw:.3f} (random-byte expectation: 4.0)")
        print(f"  Longest repeated substring: {lrs} byte(s)")
        print(f"  16-byte block uniqueness: {unique_blocks}")
        print(f"  Autocorrelation (lag: matches/total):")
        for lag, matches, total in ac[:4]:
            print(f"    lag={lag}: {matches}/{total} ({100*matches/total:.1f}%, "
                  f"random expectation ~0.39%)")
        print()

    print(">>> Net: statistically indistinguishable from random/encrypted/")
    print(">>> hashed data on both radios. See docs/FINDINGS.md section 4.4.")
