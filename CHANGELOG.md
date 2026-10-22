# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-22

### Added

- `pc_check: :ignore` option of `Sinetex.open/2`: skips the C10 check and picks
  the sender by C13 alone, for counterparties that do not fill C10/C12 with the
  PCs of the certificates. The default (`:strict`) is unchanged.
- `serial:` option of `Sinetex.Certificate.load/2` and `Sinetex.Identity.load/3`:
  the number to write in C11/C13, for certificates whose serial number does not
  fit the field or that a counterparty identifies by another number.
- `compression_level:` option of `Sinetex.seal/2`. Without it the output is the
  same as before.
- How to read a PKCS#12 file (`.pfx`, `.p12`), in the README and the guide.

### Changed

- `Sinetex.open/2` accepts C07 = `0x00` when the content is not encrypted
  (C04 2, 3, 6 and 10), since there is no symmetric key to select. Other
  invalid values still give `0x04`.
- The "empty" header (§5.6.3) is also recognized with the serial number zero
  written as text (32 × `"0"`) in C11 and C13. It still needs
  `allow_clear: true`.
- `inspect/1` of a `Sinetex.Error` shows the codes in `reason` as numbers, not
  as a charlist.

## [0.1.0] - 2026-10-21

### Added

- `Sinetex.seal/2` and `Sinetex.open/2`: Security Protocol v3 (AES-256-GCM) and
  v2 (3DES), every C04 value, the "empty" header (`allow_clear: true`).
- `Sinetex.error_envelope/2` for GEN0004 answers.
- Error table of the manual (`Sinetex.Error`), with the "lowest code wins" rule.
- `Sinetex.Identity` and `Sinetex.Certificate`: PEM and DER, PKCS#1 and PKCS#8
  (also encrypted), the PC code from `OU=CSPB-n`.
- GZIP and ZIP compression; format detected by magic bytes when receiving;
  output size limit.
- `c14_errors: :uniform`, `trim_padding`, `known`, `certificate_check`,
  `max_input_bytes` and `max_output_bytes` options of `Sinetex.open/2`.
- `Sinetex.Header` and `Sinetex.Serial` for the header format.
- `tools/header_dump.exs`, to inspect the header of an envelope without keys.

[0.2.0]: https://github.com/openspb/sinetex/releases/tag/v0.2.0
[0.1.0]: https://github.com/openspb/sinetex/releases/tag/v0.1.0
