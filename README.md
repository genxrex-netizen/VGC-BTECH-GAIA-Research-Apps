# VGC/Benshi GAIA Protocol Research

GAIA protocol reverse-engineering for VGC/Benshi-family ham radios (BTech
UV-Pro, VGC VR-N7600, RadioOddity GA-5WB, Vero VR-N76/VR-N7500). This is the
Bluetooth app-control protocol these radios use — not to be confused with the KISS TNC,
DMR, APRS, or the RDA1846S RF chip's own register interface (though one GAIA
command reads directly from it — see below).

Two independent open-source GAIA clients already exist —
[khusmann/benlink](https://github.com/khusmann/benlink) (Python) and
[Ylianst/HTCommander](https://github.com/Ylianst/HTCommander)
(Dart/Flutter, formerly C#) — and this project builds directly on both.
This repo focuses specifically on the handful of GAIA commands **neither
project has ever decoded**, using live differential testing against two
real, physically owned radios (one VR-N7600, one UV-Pro).

## Status

| Command | ID | Status | Finding |
|---|---|---|---|
| `GET_DEV_ID` | 1 | 🔴 Open | 64-byte per-device blob, statistically indistinguishable from random/encrypted/hashed data. Not a raw P-256 EC point. |
| `READ_ADVANCED_SETTINGS` | 29 | 🟡 Structurally mapped, field meanings open | Confirmed 20-byte prefix + 9-byte header + 5×18-byte record table + 3-byte trailer. Contains a firmware-constant lookup table and several isolated per-model calibration candidates. |
| `READ_RDA1846S_AGC` | 37 | 🟢 **Closed** | Confirmed static firmware/hardware constant, not a live AGC register readout — verified under both idle and live-RF-signal conditions on two radio models. |

Full technical write-up, confidence-tagged findings, and reproduction
instructions: **[`docs/FINDINGS.md`](docs/FINDINGS.md)**.

## Reproducing the findings

All specific byte values and claims are checked programmatically against
real captured hex, not hand-derived:

```bash
python3 scripts/check_devid_curve.py          # GET_DEV_ID: P-256 curve check + entropy battery
python3 scripts/analyze_advanced_settings.py  # READ_ADVANCED_SETTINGS: record-boundary decomposition
```

Raw captures live in [`captures/raw_captures.json`](captures/raw_captures.json)
— frames from both radios for every command discussed.

## Why this exists

Both radios use the same OEM reference design and protocol family; ~60 of
the ~76 named GAIA commands have never been exercised in any public client.
Most are genuinely uninteresting (FM broadcast tuner control, canned
messages), but a few resisted every non-destructive technique tried,
including cross-checking two independent chip-register hypotheses against
live captures and a from-scratch curve-equation test. This repo documents
that process and its evidence so the remaining unknowns are precisely
scoped instead of vaguely "opaque."

## Contributing

See the "What would help next" and "Contributing" sections of
[`docs/FINDINGS.md`](docs/FINDINGS.md). Firmware images, BLE HCI captures of
the OEM app, or corrections (with reproducible bytes) are all welcome via
issue or PR.

## Author

Maintained by **KO4KKS** (licensed amateur radio operator), using
personally-owned VR-N7600 and UV-Pro hardware. This is amateur/hobbyist
protocol research done for interoperability and community documentation
purposes — no vendor systems or third-party devices are involved.

## License

MIT — see [`LICENSE`](LICENSE).
