# GAIA Protocol — Detailed Findings

Full technical write-up of the reverse-engineering work in this repo. See
the top-level `README.md` for a quick-start summary.

**Methodology note:** every specific byte value or claim below can be
reproduced with the scripts in `scripts/` against the raw captures in
`captures/raw_captures.json`. Findings are tagged by confidence
(High/Medium/Low) and basis (observed / tested / reasoning / speculation) —
please keep that discipline when contributing, and verify before trusting
any specific hex value quoted in an issue or PR discussion (a transposed
digit is an easy, hard-to-notice mistake — this project has already caught
one in its own process).

---

## 1. System background

**Hardware:** two handheld ham radios, same protocol family, different
vendors/models:
- **VGC VR-N7600** ("ob" in captures) — firmware 0.9.2
- **BTech UV-Pro** ("pi4" in captures) — firmware 0.9.3

Both use **GAIA**, a vendor app-control protocol tunneled over Bluetooth
Classic RFCOMM (SPP). Same protocol family as several rebadged radios from
the same OEM reference design: VR-N7600, BTech UV-Pro, RadioOddity GA-5WB,
Vero VR-N76, VR-N7500.

The RF transceiver chip in both radios is the **RDA1846S**, a documented
chip with a public datasheet — a separate, lower-level protocol from GAIA
itself.

**Frame format** (confirmed across ~76 commands in the enum):
```
00 02 80 <cmd_id: 1 byte> <status_byte: 1 byte> <payload...>
```
`00 02` = fixed prefix, `80` = reply flag, `status_byte` = `00` on success.

**Command ID reference** (agrees exactly with `khusmann/benlink` and
`Ylianst/HTCommander`'s enums):

| ID | Name |
|---|---|
| 1 | `GET_DEV_ID` |
| 4 | `GET_DEV_INFO` |
| 10 | `READ_SETTINGS` (fully decoded elsewhere — see §6) |
| 29 | `READ_ADVANCED_SETTINGS` |
| 30 | `WRITE_ADVANCED_SETTINGS` |
| 37 | `READ_RDA1846S_AGC` |
| 38 | `WRITE_RDA1846S_AGC` |
| 39 | `READ_FREQ_RANGE` |
| 54 | `GET_DID` (confirmed = device model ASCII string, e.g. `"VR-N7600"`) |
| 63 | `READ_ADVANCED_SETTINGS2` |
| 64 | `WRITE_ADVANCED_SETTINGS2` |
| 74 | `SET_DEV_ID` |

---

## 2. Prior art

- **`khusmann/benlink`** (github.com/khusmann/benlink) — independent
  open-source Python reverse-engineering of this exact protocol family.
  Checked exhaustively (all branches, full history, issues/PRs) as of
  commit `c4b9d22` (2026-06-13): no decoder exists for `GET_DEV_ID`,
  `READ_ADVANCED_SETTINGS`, or `READ_RDA1846S_AGC` on any branch, ever.
- **`Ylianst/HTCommander`** (github.com/Ylianst/HTCommander) — second,
  independent open-source GAIA client, recently rewritten from Windows/C#
  into cross-platform Dart/Flutter, with a companion `HTCommanderWeb` repo.
  Same three gaps confirmed in the new codebase too (as of 2026-07-13) —
  `GET_DEV_ID` now has a handler that stores the payload as an opaque hex
  blob for display, but no actual decode; the other two have no handling
  at all.
- **RDA1846S chip datasheet + two third-party Arduino I2C libraries**
  (`phishman/RDA1846`, `thaaraak/rda1846`) — documents most chip registers,
  but not register `0x32` ("AGC"), which both libraries independently
  reverse-engineered anyway.

---

## 3. `GET_DEV_ID` (command 1) — OPEN

64-byte high-entropy payload, completely different per physical device,
stable across repeated reads.

| Confidence | Finding |
|---|---|
| High (observed) | Exactly 64 bytes on both radios, stable across repeated captures. |
| High (observed) | Completely different between the two physical units — no shared-keystream pattern under XOR. |
| High (tested) | Fails the secp256r1 (P-256) curve equation under all 4 split/endian combinations — not a raw uncompressed EC point in that encoding. Run `scripts/check_devid_curve.py` to reproduce. |
| High (tested) | Statistically indistinguishable from random/encrypted/hashed data — entropy, Hamming weight, autocorrelation, and block uniqueness all match the expected profile for high-quality random bytes. Same script reproduces this. |
| Medium (reasoning) | Ruled out as a raw Curve25519/X25519 or Ed25519 public key on length grounds alone — both use 32-byte keys, not 64. |
| Low (speculation) | Candidates: a 512-bit secret/seed, a hash/KDF output, an encrypted provisioning record, or a certificate/identity-object fragment. Unlikely to be resolved from packet captures alone — see §7. |

---

## 4. `READ_ADVANCED_SETTINGS` (command 29) — OPEN, structurally mapped

### 4.1 Confirmed structure

The 122-byte payload decomposes as:
```
[20-byte freq-range prefix, byte-identical to READ_FREQ_RANGE's (cmd 39) full payload]
+ [102-byte tail]
```

The 102-byte tail further decomposes exactly as:
```
9-byte header + 5 x 18-byte records + 3-byte trailer = 9 + 90 + 3 = 102
```
Found by locating an exact repeated 7-byte marker (`ff ff ff f0 00 00 00`)
at tail-local offsets 45 and 63 — an 18-byte stride, reproduced
independently on both radios — then walking that stride across the full
tail length. Run `scripts/analyze_advanced_settings.py` to reproduce every
number in this section.

### 4.2 Per-record diff table (ob vs pi4)

| Record | ob (18 bytes) | pi4 (18 bytes) | Differing indices | Same/18 |
|---|---|---|---|---|
| 0 | `19283c61ff26191b1d1f2123252729433435` | `0a163f79ff26191b1d1f2123252729542535` | 0,1,2,3,15,16 | 12 |
| 1 | `1abcceeeee00000554445567ffff01555574` | `1a1cceeeee000003234679adffff01523435` | 1,7,8,9,10,11,15,16,17 | 9 |
| 2 | `fffffff0000000065555568afffff042237f` | `fffffff00000000b86678acdfffff042237f` | 7,8,9,10,11 | 13 |
| 3 | `fffffff00000000fca44abdffffff0002540` | `fffffff00000000fb999abdffffff0a60100` | 8,9,15,16,17 | 13 |
| 4 | `0000000000978beffffd8abbacefff000000` | `000000000000000fffffffffffff00000000` | 5,6,7,9,10,11,12,13,14 | 9 |

Header (9 bytes): `be be 13 64 13 57 0d` (identical on both radios) + 2
model-varying bytes. Trailer (3 bytes): `00 00 00` on both — fully
invariant.

### 4.3 The invariant arithmetic run

A 9-byte perfect step-+2 arithmetic run, byte-identical on both radios:
`19 1b 1d 1f 21 23 25 27 29` (tail offsets 15-23, decimal 25-41).

| Confidence | Finding |
|---|---|
| High (observed, exact) | Byte-identical across two different radio models. |
| High (reasoning) | Not per-device/per-model calibration data — a fixed constant shared by the whole product line's firmware. |
| Medium (reasoning) | Most parsimonious explanation for a clean monotonic step-2 integer run: an index/offset lookup table, not a physical RF quantity. |
| **Rejected as unsupported** | A "sanity check" once proposed this maps to "RF step intervals / CTCSS/DCS clock boundaries / step-attenuator thresholds." **No mechanism supports this** — real CTCSS tones aren't integer Hz values, DCS codes are octal, and attenuator steps are typically powers of 2 in dB, not sequential odd integers. Documented here explicitly so it isn't mistaken for a settled fact. |

### 4.4 Active-inference testing (all null)

Every real physical setting change tested (channel memory edit, squelch to
min, TX time limit to 3 min, display brightness to max on both radios in
both directions, Dual Watch, PTT Follow, Digital Mute) came back
byte-for-byte identical to baseline against the *whole* 122-byte payload —
before the record structure above was known. **Not yet retested at the
per-record level** — re-running any of these against records 2/3
specifically (the cleanest candidates, fewest differing bytes) would be
more informative than a whole-payload diff.

### 4.5 Working theory

Not a monolithic blob — a structured table with proven invariant firmware
constants (header's first 7 bytes, the arithmetic run, the trailer, most of
records 2-4) alongside a small number of isolated per-model-varying byte
spans (the real calibration-field candidates). Two independent technique
classes are still needed to formally close this out (see §7 for what's been
tried and what remains).

---

## 5. `READ_RDA1846S_AGC` (command 37) — **CLOSED**

**Verdict: static firmware/hardware constant, not a live RF/AGC readout,
despite the command name.**

Payload `20 a2 e8 00` (4 bytes) is identical across:
- Two different radio models (VR-N7600, UV-Pro)
- Idle (no signal) conditions
- **Live signal conditions** — captured while a second radio held PTT and
  transmitted directly into the radio under test, on both models

All 4 conditions (2 radios × idle/live-signal) returned the byte-identical
payload. This satisfies a 2-independent-technique-class bar (idle/
differential testing + live-signal testing under real RF conditions) —
closed, not just "untested under signal."

The RDA1846S register `0x32` ("AGC") hypothesis, from two independent
third-party Arduino I2C libraries (default value `0x7497`, bits[11:6] =
`agc_target_pwr`), does not match under any byte-aligned big/little-endian
slice — tested and rejected.

---

## 6. Already resolved (for context, not open questions)

- `READ_SETTINGS` (cmd 10) is fully decoded (~35 fields: squelch, TX time
  limit, mic/BT-mic gain, tail elimination, Dual Watch, PTT Follow, Digital
  Mute, screen timeout, and more) — not one of the commands this repo is
  tracking, but relevant context: several "advanced-sounding" field names
  live here, not in cmd 29, despite the naming.
- Display brightness confirmed untracked by cmd 10, 29, or 33
  (`READ_BSS_SETTINGS`) in either direction on either radio model.
- "AI NR" and "VOX" exist on the VR-N7600 but are confirmed absent from the
  UV-Pro's official manual — a hardware/firmware difference, not a decode
  gap.
- `GET_APRS_PATH` (cmd 72) confirmed empty on both radios.

---

## 7. What would help next

For `GET_DEV_ID`:
- Curve25519/Ed25519 curve-equation checks against the same split
  hypotheses `check_devid_curve.py` uses for P-256.
- Firmware-level ground truth (see below) — packet analysis alone is
  unlikely to distinguish "secret," "hash," and "encrypted record."

For `READ_ADVANCED_SETTINGS`:
- Word-alignment reinterpretation (16-bit/32-bit, both endians) of
  records 2 and 3's isolated variable-byte spans specifically.
- A **factory-reset differential** (destructive — bytes that survive a
  reset are burned-in calibration; bytes that change are settings/
  defaults) or a **passive BLE HCI capture of the OEM app** checking
  whether it ever issues `WRITE_ADVANCED_SETTINGS` (cmd 30) — either would
  supply the second independent technique class this command still needs.

**Highest-likely-yield remaining avenue for both open commands:**
application-MCU firmware extraction (distinct from the RDA1846S chip work
and from a phone-app BLE capture — this targets the radio's own firmware
image). Given the packet evidence now looks like a direct in-memory
struct/table dump, the corresponding C struct definition and command
dispatcher plausibly exist verbatim in the firmware binary. Not yet
attempted by this project — no firmware image obtained. If you have one,
search for a `switch(cmd)`-style dispatcher and the literal length
constants `122`, `64`, `20`, `18`, `9`.

---

## 8. Contributing

Issues and PRs welcome — especially:
- A firmware image for either radio (or a pointer to where to get one)
- BLE HCI capture logs from the OEM app's connection handshake or settings
  screens
- A correction, with reasoning and reproducible bytes, to anything above

Please keep the confidence-tagging convention (High/Medium/Low,
observed/tested/reasoning/speculation) for new claims, and verify specific
byte values against `captures/raw_captures.json` before relying on them —
this project has already caught one transcription error in its own
process, and it's an easy mistake to repeat.
