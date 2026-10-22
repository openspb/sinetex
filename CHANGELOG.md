# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
