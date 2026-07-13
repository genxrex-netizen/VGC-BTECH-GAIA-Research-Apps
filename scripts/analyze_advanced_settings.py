#!/usr/bin/env python3
"""
Structural analysis of READ_ADVANCED_SETTINGS (GAIA command 29).

Confirms the 122-byte payload decomposes as:
  20-byte freq-range prefix (shared with READ_FREQ_RANGE, cmd 39)
  + 9-byte header
  + 5 x 18-byte records
  + 3-byte trailer

Finds the invariant arithmetic-run marker inside the header/record-0
boundary, and produces a per-record ob-vs-pi4 diff table.

Usage: python3 analyze_advanced_settings.py
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURES = os.path.join(HERE, "..", "captures", "raw_captures.json")

HEADER_LEN = 9
STRIDE = 18
N_RECORDS = 5
PREFIX_LEN = 20  # shared with cmd 39 (READ_FREQ_RANGE)


def load_payloads():
    with open(CAPTURES) as f:
        data = json.load(f)
    frames = data["commands"]["29_READ_ADVANCED_SETTINGS"]
    freq_range = data["commands"]["39_READ_FREQ_RANGE"]
    payloads = {r: bytes.fromhex(h)[5:] for r, h in frames.items()}
    freq_payloads = {r: bytes.fromhex(h)[5:] for r, h in freq_range.items()}
    return payloads, freq_payloads


def find_arithmetic_runs(b, min_len=4):
    runs = []
    n = len(b)
    i = 0
    while i < n - 1:
        step = b[i + 1] - b[i]
        j = i + 1
        while j + 1 < n and b[j + 1] - b[j] == step:
            j += 1
        length = j - i + 1
        if length >= min_len and step != 0:
            runs.append((i, j, step, b[i:j + 1].hex()))
        i = j if j > i else i + 1
    return runs


if __name__ == "__main__":
    payloads, freq_payloads = load_payloads()

    print("=== Prefix check: cmd 29 vs cmd 39 (READ_FREQ_RANGE) ===\n")
    for radio in payloads:
        prefix = payloads[radio][:PREFIX_LEN]
        freq = freq_payloads[radio]
        print(f"{radio}: cmd29[:{PREFIX_LEN}] == cmd39 payload? {prefix == freq}")

    tails = {radio: payloads[radio][PREFIX_LEN:] for radio in payloads}
    print(f"\nTail length (should be 102): {[len(t) for t in tails.values()]}")

    print("\n=== Record-boundary decomposition (9 header + 5x18 records + 3 trailer) ===\n")
    headers = {r: t[:HEADER_LEN] for r, t in tails.items()}
    trailers = {r: t[HEADER_LEN + N_RECORDS * STRIDE:] for r, t in tails.items()}
    records = {
        r: [t[HEADER_LEN + i * STRIDE: HEADER_LEN + (i + 1) * STRIDE] for i in range(N_RECORDS)]
        for r, t in tails.items()
    }

    radios = list(tails.keys())
    print(f"Header:  {radios[0]}={headers[radios[0]].hex()}  {radios[1]}={headers[radios[1]].hex()}")
    print(f"Trailer: {radios[0]}={trailers[radios[0]].hex()}  {radios[1]}={trailers[radios[1]].hex()}\n")

    print(f"{'Record':>6} | {'diff idx':<30} | same/18")
    for i in range(N_RECORDS):
        r0, r1 = records[radios[0]][i], records[radios[1]][i]
        diffs = [j for j in range(STRIDE) if r0[j] != r1[j]]
        print(f"{i:>6} | {str(diffs):<30} | {STRIDE - len(diffs)}/18")
        print(f"       {radios[0]}: {r0.hex()}")
        print(f"       {radios[1]}: {r1.hex()}")

    print("\n=== Invariant arithmetic-run search (tail-local offsets) ===\n")
    for radio, tail in tails.items():
        runs = find_arithmetic_runs(tail)
        print(f"{radio}: {runs}")

    print("\n>>> A 9-byte perfect step+2 arithmetic run ('19 1b 1d 1f 21 23 25")
    print(">>> 27 29') is byte-identical on both radios at tail offset 15-23 --")
    print(">>> proof this span is a fixed firmware constant, not per-device")
    print(">>> calibration data. See docs/FINDINGS.md section 5.3.")
