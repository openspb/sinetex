# Specification: the RSFN security envelope (Security Protocol, versions 2 and 3)

| | |
|---|---|
| **Applies to** | Version 0.1 of the library |
| **Normative source** | Banco Central do Brasil, *Manual de Segurança do SFN*, Volume I, version 6.00 (2026-06-08). Version 6.00 added Volume II (Pix) and left chapter 5 as it was in version 5.07 (2025-12-19), so the section numbers below apply to both |
| **Scope of this document** | What the library does with the bytes: build and open the 588-byte header, sign, encrypt, compress, verify and report errors |

This document is written **only from the public manual of Banco Central**. Each
rule shows where it comes from:

| Mark | Meaning |
|---|---|
| **[N §x]** | Normative: in the manual, in the section shown |
| **[P]** | Market practice: the manual is silent, or differs from what counterparties do. **Must be confirmed with real traffic** before version 1.0 (§9) |
| **[L]** | Library decision: the manual does not require it; we chose it and document it |

MUST, MUST NOT and MAY are used as in RFC 2119. Sections of the manual always
appear inside a mark (**[N §5.1.4]**); a bare "§", as in "(§3.1)", points to a
section of this document.

---

## 1. Scope

**In:**
- the 588-byte security header, fields C01–C15 [N §5.1];
- Security Protocol **version 2** (3DES) and **version 3** (AES-256-GCM) [N §5.1.2, §5.1.3];
- sending [N §5.2] and receiving [N §5.3];
- special treatment indicators, C04 [N §5.6];
- error codes, C03 / EGEN99xx [N §5.5];
- optional compression before signing (ZIP and GZIP).

**Out:**
- Security Protocol version 1 (manuals before version 3.0);
- transport: the 512-byte MQSeries header (Annex A), Connect:Direct, FTP/SFTP;
- certificate life cycle: registration through STA, activation (GEN0006/GEN0007), revocation lists [N §4.4, §4.5];
- content and encoding of the XML (Catálogo de Serviços do SFN) [N §5.2.2]: the library works on **bytes** and does not read the message;
- Pix (Volume II), which uses a different scheme (XMLDSig + mTLS);
- key storage (HSM, Vault, PKCS#12). The library receives keys already loaded;
- the audit record [N §5.4], not implemented yet.

---

## 2. Structure

```
envelope = header (588 bytes) ‖ body
```

The body starts at position 589 (1-based) [N §5.3.4]. The header is binary,
with no code page [N §5.2.1].

### 2.1 Header fields [N §5.1, Table 1 and Annex A]

Offsets are **0-based** (the manual uses 1-based positions; the "Manual" column
repeats them).

| Field | Offset | Size | Manual | Content |
|---|---|---:|---|---|
| C01 | 0–1 | 2 | 001–002 | Header size: `0x02 0x4C` (588) |
| C02 | 2 | 1 | 003 | Protocol version: `0x00` clear text, `0x02`, `0x03` |
| C03 | 3 | 1 | 004 | Error code (§6). `0x00` = no error |
| C04 | 4 | 1 | 005 | Special treatment (§4) |
| C05 | 5 | 1 | 006 | Reserved: `0x00` |
| C06 | 6 | 1 | 007 | Recipient's asymmetric key: `0x01` RSA-1024, `0x02` RSA-2048 |
| C07 | 7 | 1 | 008 | Symmetric key: `0x01` 3DES (v2 only), `0x02` AES-256 (v3 only) |
| C08 | 8 | 1 | 009 | Sender's asymmetric key: `0x01` RSA-1024, `0x02` RSA-2048 |
| C09 | 9 | 1 | 010 | Hash: `0x02` SHA-1, `0x03` SHA-256 |
| C10 | 10 | 1 | 011 | PC of the recipient's certificate (§3.2) |
| C11 | 11–42 | 32 | 012–043 | Serial number of the recipient's certificate (§3.1) |
| C12 | 43 | 1 | 044 | PC of the sender's certificate (§3.2) |
| C13 | 44–75 | 32 | 045–076 | Serial number of the sender's certificate (§3.1) |
| C14 | 76–331 | 256 | 077–332 | Symmetric key encrypted with RSAES-PKCS1-v1_5 (§5) |
| C15 | 332–587 | 256 | 333–588 | Authentication cryptogram: RSASSA-PKCS1-v1_5 (§5) |

**Byte order of C01:** the manual writes `024CH`. We read it as big-endian
(`0x02`, `0x4C`) **[P]**.

### 2.2 Values the library sends [L]

The library sends only RSA-2048 and SHA-256, because only RSA-2048
certificates are accepted [N §4.4.16] and SHA-256 is mandatory with 2048-bit
keys [N §5.1.7]:

| | v2 | v3 |
|---|---|---|
| C02 | `0x02` | `0x03` |
| C06 / C08 | `0x02` | `0x02` |
| C07 | `0x01` | `0x02` |
| C09 | `0x03` | `0x03` |

When receiving, RSA-1024 (`0x01` in C06/C08, with the last 1024 bits of C14/C15
zeroed [N §5.1.5]) and SHA-1 are **rejected** with the matching code (§6) **[L]**.

---

## 3. Certificate identification

### 3.1 Serial number (C11, C13) [N §5.1.4, §5.2.6]

1. Take the serial number of the X.509 certificate as an **integer**.
2. Write it in **uppercase** hexadecimal, with no separators.
3. Pad it **on the left** with the ASCII character `'0'` (`0x30`) up to 32 bytes.

Examples from the manual: `5D77 DA7B 6F02 EFA1 EDDA 741E 78FF 3508` →
`5D77DA7B6F02EFA1EDDA741E78FF3508`; `3B3B C056` →
`0000000000000000000000003B3BC056`.

Each byte MUST be in `0x30–0x39` or `0x41–0x46` [N §5.1.4]. When receiving, a
byte outside that range makes the serial number invalid (§6) **[L]**.

A serial number longer than 16 bytes (32 hex digits) does not fit in the
field; RFC 5280 allows up to 20. The library **refuses** such a certificate
when loading it **[L]**.

### 3.2 PC code (C10, C12) [N §5.1, Table 1; §4.2.6]

| Code | PC |
|---|---|
| `0x01` | SPB-Serpro |
| `0x02` | SPB-Certisign |
| `0x03` | Pessoas Físicas (reserved for STR-WEB [N §5.1.6]) |
| `0x04` | SPB-Serasa |
| `0x05` | SPB-CAIXA |
| `0x06` | SPB-Valid |
| `0x07` | SPB-Soluti |

SPB-style certificates carry `OU=CSPB-n` in the issuer [N §4.2.6], where `n` is
the code in the table. The library **derives** the code from that field when
it exists and **requires it explicitly** when it does not, which is the case of
certificates issued outside the SPB scheme for specific clearing houses **[L]**.

A code given explicitly always wins over the derived one. Without `OU=CSPB-n`
and without a code, loading the certificate fails with `:pc_code_required`
**[L]**. The library does not try to recognize the certification authority by
the issuer name.

---

## 4. Special treatment indicator (C04) [N §5.6]

| C04 | Meaning | Compressed | Signed | Encrypted |
|---:|---|:-:|:-:|:-:|
| 0 | Message or file, signed and encrypted (default) [N §5.6.1] | – | ✔ | ✔ |
| 1 | Uses a certificate **not activated yet** (GEN0001/GEN0008 optional, GEN0006 mandatory) | – | ✔ | ✔ **[P]** |
| 2 | Not encrypted: public broadcast, no recipient | – | ✔ | – |
| 3 | Not encrypted, security related (e.g. GEN0004 [N §5.5.7]) | – | ✔ | – |
| 4 | File **not** compressed, usually an answer | – | ✔ | ✔ **[P]** |
| 6 | File not compressed, not encrypted, public [N §5.7.13] | – | ✔ | – |
| 8 | File **compressed** | ✔ | ✔ | ✔ |
| 10 | File compressed, not encrypted, public [N §5.7.13] | ✔ | ✔ | – |

- Every value is signed, because every message is signed except in the cases
  of §4.1.
- The manual does not say explicitly that 1 and 4 are encrypted; that is what
  is observed in the market **[P]**.
- Any other value gives error `0x13` (§6). For the other header checks, an
  unknown value counts as encrypted **[L]**.

### 4.1 The "empty" header [N §5.6.3]

The GEN0001 (echo) may have **every field zeroed except C01**. Its body is then
in clear text, neither signed nor encrypted. The library recognizes this case
only when the receiver asks for it (`allow_clear: true`) and then returns the
body as it is, marked `:clear`. Otherwise the envelope is rejected with `0x02`,
so that an application that does not expect clear text never gets it by
accident **[L]**.

### 4.2 C14, C06/C07 and C10/C11 without encryption

The manual does not say how to fill C14 or C06/C07 when C04 means "not
encrypted". The library sends **C14 as 256 bytes `0x00`** and keeps C06/C07 at
the values of the version **[P]**. When receiving, C14 is ignored in that case.

Without a recipient (allowed only when there is no encryption), C10 is `0x00`
and C11 is 32 bytes `0x00` **[L]**.

---

## 5. Sending [N §5.2]

**Input:** content `P` (bytes), the sender's private key and certificate, the
recipient's certificate (not needed when there is no encryption), version (2
or 3), C04 and compression format.

1. **Compression.** If C04 ∈ {8, 10}, `D = compress(P)` (§7). Otherwise `D = P`.
2. **Padding.**
   - v2: append `0x00` to `D` up to a multiple of 8 bytes [N §5.2.3, §5.7.14].
   - v3: **no** padding [N §5.2.3].
3. **Signature (C15).** `C15 = RSASSA-PKCS1-v1_5-SIGN(sender_private_key, SHA-256, D)`
   [N §5.1.1, §5.2.4, §5.2.7]. The signature covers the content **after**
   compression and **with** the padding.
4. **Encryption.** Only if C04 means encrypted (§4).
   - Generate a **new symmetric key for each message or file** [N §5.2.8], with
     a cryptographically secure generator.
   - **v2** [N §5.1.2, §5.1.2.1, Annex A notes 1–2]:
     - `K` = 24 random bytes, with **odd parity** set on each byte;
     - `IV = K[0..7]` (the first 8 bytes of the key);
     - `E = 3DES-EDE3-CBC(K, IV, D)`, with no extra padding, since `D` is a multiple of 8;
     - `C14 = RSAES-PKCS1-v1_5-ENCRYPT(recipient_public_key, K)` (24 bytes).
   - **v3** [N §5.1.3–§5.1.3.4]:
     - `K` = 32 random bytes; `N` = 12 random bytes (nonce/IV);
     - `(C, T) = AEAD_AES_256_GCM(K, N, AD = empty, D)` (RFC 5116), with a 16-byte tag `T`;
     - `E = C ‖ T` (the tag goes **at the end** of the body, not in the header);
     - `C14 = RSAES-PKCS1-v1_5-ENCRYPT(recipient_public_key, K ‖ N)` (44 bytes).
   - No encryption: `E = D` and C14 = 256 × `0x00` (§4.2).
5. **Header.** Fill C01–C13 (§2, §3); C03 = `0x00`; C05 = `0x00`.
6. **Output:** `header ‖ E`.

The order compress → sign → encrypt comes from [N §5.2.4–§5.2.9].

---

## 6. Receiving and errors [N §5.3, §5.5]

### 6.1 Error table [N §5.5.1]

| C03 | GEN0004 | Field | Cause |
|---|---|---|---|
| `0x01` | EGEN9901 | C01 | Header size zero or incompatible |
| `0x02` | EGEN9902 | C02 | Invalid or incompatible version |
| `0x03` | EGEN9903 | C06 | Recipient's key algorithm invalid or different from the certificate |
| `0x04` | EGEN9904 | C07 | Invalid symmetric algorithm |
| `0x05` | EGEN9905 | C08 | Sender's key algorithm invalid or different from the certificate |
| `0x06` | EGEN9906 | C09 | Hash algorithm invalid or does not match |
| `0x07` | EGEN9907 | C10 | Invalid PC of the recipient's certificate |
| `0x08` | EGEN9908 | C11 | Invalid serial number of the recipient's certificate |
| `0x09` | EGEN9909 | C12 | Invalid PC of the certificate |
| `0x0A` | EGEN9910 | C13 | Invalid serial number of the sender's certificate |
| `0x0B` | EGEN9911 | C15 | Invalid authentication cryptogram |
| `0x0C` | EGEN9912 | C12/C13 | Certificate does not belong to the sender of the message |
| `0x0D` | EGEN9913 | C14 | Error extracting the symmetric key |
| `0x0E` | EGEN9914 | C14 | Error from the symmetric algorithm |
| `0x0F` | EGEN9915 | body | Size not a multiple of 8 (v2 only) |
| `0x10` | EGEN9916 | C12/C13 | Certificate not activated |
| `0x11` | EGEN9917 | C12/C13 | Certificate expired or revoked |
| `0x12` | EGEN9918 | – | Generic error of the security layer |
| `0x13` | EGEN9919 | C04 | Invalid or incompatible special treatment indicator |
| `0x14` | EGEN9920 | C12/C13 | Invalid certificate (use the one "to be activated" in GEN0006) |
| `0xFF` | – | – | Error outside the security scope (e.g. BCMSG) [N §5.5.8] |

When there is more than one error, the **lowest code** is reported [N §5.5.3].

### 6.2 Algorithm

**Input:** envelope, own private key and certificate, and the expected
sender's certificate (or a set of accepted certificates). Optionally, other
known certificates and a certificate check supplied by the caller.

**Before the header [L]:** an envelope larger than the configured input limit
gives `0x12`.

**Phase A: header consistency.** Every check runs, and the lowest code found is
reported:

| Check | Error |
|---|---|
| Envelope shorter than 588 bytes, or C01 ≠ `0x024C` | `0x01` |
| Empty header (§4.1) | with `allow_clear`, return the body as clear text, without the checks below; otherwise `0x02` **[L]** |
| C02 ∉ {`0x02`, `0x03`}; `0x00` ("clear text") is accepted only in the empty header **[L]** | `0x02` |
| C06 ≠ `0x02`, or different from the size of my certificate's key | `0x03` |
| C07 invalid, or incompatible with C02 (v2 ↔ `0x01`, v3 ↔ `0x02`) **[L]** | `0x04` |
| C08 ≠ `0x02`, or different from the size of the sender's key | `0x05` |
| C09 ≠ `0x03` | `0x06` |
| C10 ≠ PC of my certificate | `0x07` |
| C11 ≠ serial number of my certificate, or not in the format of §3.1 | `0x08` |
| C12 = `0x00`, or C13 matches an expected or known certificate whose PC is not C12 **[L]** | `0x09` |
| C13 not in the format of §3.1, or matches no known certificate | `0x0A` |
| C12/C13 match a known certificate that is not an expected sender **[L]** | `0x0C` |
| C04 ∉ {0, 1, 2, 3, 4, 6, 8, 10} | `0x13` |
| The caller's certificate check (§6.4) | the code it returns |

The checks of C06, C10 and C11 apply only when the content is encrypted.

**Phase B: cryptography.** In order, stopping at the first error:

1. v2 with encryption and a body whose size is not a multiple of 8 → `0x0F`.
   v3 with encryption and a body shorter than 16 bytes → `0x0E` **[L]**. v2
   when the host has no 3DES → `0x12` **[L]**. Without encryption the size of
   the body is not checked **[L]**.
2. Decrypt C14 with my private key [N §5.3.3]. A failure, or a key of a size
   other than 24 (v2) or 44 (v3) bytes → `0x0D`, as the manual defines. With
   the option `c14_errors: :uniform`, this failure is reported as `0x0E`, like
   a failure in the body (see §8, padding oracle) **[L]**.
3. Decrypt the body [N §5.3.4]: v3 with an invalid GCM tag → `0x0E`; v2 has no
   check at this step.
4. Verify C15 over the decrypted content **with padding** [N §5.3.5, §5.3.6] → `0x0B`.
5. If C04 ∈ {8, 10}: decompress (§7). Failure, or output above the configured
   limit → `0x12` **[L]**.

`0x0B` is lower than `0x0D` and `0x0E`, but it can only be checked after
decryption. If decryption fails, its failure is reported.

**Padding in the output (v2):** the manual says the padding **must not be
removed** [N §5.7.14]. By default the library returns exactly the signed
content, with padding. With `trim_padding: true` it removes up to 7 trailing
`0x00` bytes **[L]**. The documentation warns that legitimate zeros at the end
of the content are removed too. For C04 ∈ {8, 10} the padding is not part of
the decompressed content, and the decompressor MUST tolerate it (§7).

### 6.3 Messages with C03 ≠ 0 and error envelopes

- A received envelope with C03 ≠ `0x00` **must not be answered** [N §5.5.5].
  The library opens it like any other and leaves the code in the header for
  the caller **[L]**.
- To answer with a GEN0004, the library builds an envelope that is **only
  signed** (C04 = 3), with C03 = the error code [N §5.5.2, §5.5.4, §5.5.7]. The
  GEN0004 XML is up to the caller.

### 6.4 Outside the library

The caller decides, through a hook called during phase A with the sender's
certificate and the header **[L]**:
- `0x10`, `0x14`: depend on the registry of active certificates [N §4.4.10, §5.3.2];
- `0x11`: revocation, by revocation list [N §4.5.11], or expiry.

Expiry follows [N §4.5.12]: the certificate stops being valid at 24:00 of the
day **before** its "valid until" date. The library MAY offer this check in a
later version; version 0.1 leaves it to the hook **[L]**.

---

## 7. Compression

| Source | Format |
|---|---|
| Manual of Banco Central | **ZIP** (C04 8 and 10 [N §5.6.2]); "ZIP with the DEFLATE method" on the SFTP servers [N §5.8.27] |
| Market practice (clearing houses) | **GZIP, RFC 1952** **[P]** |

**Receiving [P]:** the format is detected by its **magic bytes**, not by C04:
- `1F 8B` → GZIP;
- `50 4B 03 04`, `50 4B 05 06` or `50 4B 07 08` → ZIP;
- neither → the content is returned **as is**, even with C04 = 8. Answers from
  counterparties marked as compressed and arriving uncompressed have been
  observed.

**GZIP [L]:** every member is read and the outputs are concatenated, as
RFC 1952 §2.2 allows. After the last member only `0x00` bytes may follow (the
v2 padding); anything else is an error. Each member's CRC-32 and size are
checked.

**ZIP [L]:** the archive MUST have exactly one entry, stored or DEFLATE, not
encrypted and not ZIP64. The *End of Central Directory* is found even with
`0x00` bytes after it (v2 padding). The CRC-32 and the sizes in the central
directory are checked.

**Sending [L]:** **no default**. With C04 ∈ {8, 10} the caller MUST pass
`compression: :gzip` or `compression: :zip`; without it sending fails with
`:compression_required`. The right format depends on the destination, which the
library does not know. The documentation advises: clearing houses → `:gzip`;
files for the Bacen SFTP servers → `:zip` [N §5.8.27]. A ZIP has a single
DEFLATE entry, by default named `content`; the name counterparties expect is
not known yet **[P]**.

**Limits [L]:** decompression has a configurable output limit (defense against
"decompression bombs"). The input has a configurable limit too.

---

## 8. Security requirements of the implementation [L]

- **Randomness:** keys and nonces come from `:crypto.strong_rand_bytes/1`. In
  tests, an injectable generator allows deterministic vectors (KAT). It exists
  only when the library is compiled for its own test suite, so it cannot be
  turned on in production by accident.
- **Padding oracle (Bleichenbacher):** RSAES-PKCS1-v1_5 is imposed by the
  protocol, and the manual gives a failure in C14 its own code (`0x0D`). If the
  application reports that code to the sender (GEN0004), it creates an oracle.
  The library handles it this way:
  - **default = manual** (`0x0D`): the library sends nothing, the application
    decides whether to report the code, and the distinct code helps diagnose a
    sender that used the wrong certificate;
  - **option `c14_errors: :uniform`**: a failure in C14 becomes `0x0E`,
    indistinguishable from a failure in the body;
  - in both modes there is no shortcut on a C14 failure: processing continues
    with a random key up to the body step (in v2, up to the signature check),
    and the real reason is kept only in an internal field of the error, for
    logging;
  - OpenSSL 3.2 and later do "implicit rejection" in RSAES-PKCS1-v1_5
    decryption (they return a synthetic key instead of an error). So that the
    error code does not depend on the OpenSSL of the host, the library
    decrypts C14 with raw RSA and checks the PKCS#1 v1.5 encoding itself
    (RFC 8017 §7.2.2). The test suite also runs on OpenSSL 3.2+;
  - the risk and the option are documented in `SECURITY.md`.
- **No exceptions on malformed input:** every invalid envelope becomes
  `{:error, %Sinetex.Error{}}`. Invalid *options* raise `ArgumentError`, because they are
  programming errors.
- **Sender's and recipient's keys when loading:** RSA of 2048 bits
  [N §4.4.16], exponent ≠ 3 [N §4.2.7], most significant bit of the modulus = 1
  [N §4.2.8].
- **Scheduling:** for large payloads the hash is computed in chunks and the
  digest is signed, so that the BEAM scheduler is not blocked.

---

## 9. Market practice items to confirm

These points follow what is observed in the market, because the manual is
silent or differs from it. They stay marked **[P]** until they are checked
against real traffic; `tools/header_dump.exs` prints the header of an envelope
without keys, for that purpose.

1. Byte order of C01 (§2.1).
2. C04 = 1 and 4 are encrypted (§4).
3. C14 zeroed and C06/C07 filled when there is no encryption (§4.2).
4. GZIP in clearing house files; detection by magic bytes; answers marked as
   compressed that arrive uncompressed (§7).
5. Name of the entry in the ZIP the library sends (§7).
