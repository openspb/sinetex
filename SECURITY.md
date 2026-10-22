# Security

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability"). You should get
an answer within a week. Fixes are released for the latest minor version.

## What the protocol protects, and what it does not

These notes are about the protocol of the *Manual de Segurança do SFN* as
much as about this library. Read them before you decide how your application
reacts to what `Sinetex.open/2` returns.

### The header is not authenticated

The signature in C15 covers only the content, and C14 carries only the
symmetric key. Nothing protects the header itself, so anyone on the path can
change these fields without making `open/2` fail:

* **C03**, the error code. A valid message can be made to look like an error
  report, and the other way round. Do not take security decisions on C03.
* **C04**, within limits. Changing "encrypted" to "not encrypted" makes the
  signature check fail, but, for example, 0 and 4 are interchangeable, and a
  compressed file marked as not compressed is returned compressed.
* **C05**, reserved.
* **C06 and C10/C11** when the content is not encrypted.

The envelope has no timestamp, sequence number or nonce that the receiver can
check, so it gives **no replay protection**. Detecting a repeated message is up
to the application (for example, by the message identifiers in the XML).

### C14 and the padding oracle

The protocol encrypts the symmetric key with RSAES-PKCS1-v1_5, which is
vulnerable to Bleichenbacher's attack when the receiver reveals whether the
padding of C14 was valid. The manual itself creates that signal: a failure to
extract the key has its own error code (`0x0D`, EGEN9913), and the receiver is
expected to report it to the sender in a GEN0004.

With enough queries (typically tens of thousands to millions), someone who can
send envelopes to you and see your GEN0004 answers can decrypt the C14 of an
envelope they captured, and with it the content.

What the library does:

* **It never answers anyone.** Sending a GEN0004 is your application's choice.
* By default it reports `0x0D`, as the manual says, because the distinct code
  helps to diagnose a sender that encrypted to the wrong certificate, and
  because the RSFN is a closed network where such a volume of bad envelopes
  from one participant is visible.
* With **`c14_errors: :uniform`** a failure in C14 is reported as `0x0E`, the
  same code as a failure to decrypt the body, so the code is no longer an
  oracle.
* In both modes the work does not stop at a bad C14: the library goes on with
  a random key and runs the same steps as with a good key, so that the time to
  answer does not depend on the padding. This is a best-effort measure in
  Elixir, not a constant-time implementation.
* The PKCS#1 v1.5 decoding of C14 is done by the library on the raw RSA
  result, instead of by OpenSSL. OpenSSL 3.2 and later answer a bad padding
  with a synthetic key ("implicit rejection") where older versions return an
  error; doing the decoding in the library gives the same error code on every
  OpenSSL version.

If your application answers bad envelopes with a GEN0004 automatically, use
`c14_errors: :uniform`, or at least rate-limit and monitor those answers per
sender.

### Version 2

Version 2 is legacy. It uses 3DES in CBC mode with the IV taken from the key,
as the manual specifies, and has no integrity check before the signature is
verified. Prefer version 3 whenever the counterparty accepts it. 3DES may be
missing from an OpenSSL in FIPS mode; the library then returns
`:des3_unavailable` when sending and `0x12` when receiving.

### Clear text

The "empty" header (all fields zero but C01, used by the GEN0001 echo) carries
a body that is neither signed nor encrypted. `open/2` rejects it unless you
pass `allow_clear: true`, and then marks the result `protection: :clear`.
Never treat such content as coming from anyone in particular.

### Certificates

The library checks that a certificate can be used by the protocol (RSA-2048,
public exponent other than 3, serial number that fits in C11/C13) and that
the sender in C12/C13 is one of the certificates you passed in `:from`. It does
**not** check chains, validity dates, activation or revocation: those depend on
your certificate registry. Use the `:certificate_check` option of `open/2`.

### Decompression and size limits

Content is decompressed with a limit on the output (`max_output_bytes`, 512 MiB
by default). The whole envelope is held in memory; set `max_input_bytes` if the
envelope comes from a source you do not control.

### Keys in memory

Private keys are Erlang terms. The BEAM cannot wipe them from memory, and they
can end up in crash dumps. `inspect/2` of a `Sinetex.Identity` does not show the
private key, but the term itself is not hidden. Protect crash dumps and remote
shells accordingly.

### Randomness

Keys and nonces come from `:crypto.strong_rand_bytes/1`. The deterministic
generator used for known-answer tests exists only when the library is compiled
for its own test suite; it is not present when Sinetex is a dependency.
