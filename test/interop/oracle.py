#!/usr/bin/env python3
"""Independent implementation of the RSFN security envelope, used as a test oracle.

Written from docs/SPEC.md only, with Python's `cryptography` package, and
sharing no code with the Elixir library. The interop tests seal with one
implementation and open with the other, in both directions.

Usage:
  oracle.py seal --cert C --key K [--pc N] [--to CERT] [--to-pc N]
                 --version {2,3} --c04 N [--compression {gzip,zip}] IN OUT
  oracle.py open --cert C --key K [--pc N] --from CERT [--from-pc N] IN OUT

`open` prints "ok c03=<n> c04=<n> compression=<gzip|zip|none>" on success and
"error <C03 code>" on failure (exit status 1).

C14 is decrypted with plain modular exponentiation and decoded as in
RFC 8017 §7.2.2, so the result does not depend on whether the OpenSSL in use
does "implicit rejection".
"""

import argparse
import gzip
import io
import os
import re
import struct
import sys
import zipfile
import zlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # older versions of cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

HEADER_SIZE = 588
NOT_ENCRYPTED = (2, 3, 6, 10)
COMPRESSED = (8, 10)
C04_VALUES = (0, 1, 2, 3, 4, 6, 8, 10)


class EnvelopeError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# SPEC §3.1
def serial_field(cert):
    field = format(cert.serial_number, "X").rjust(32, "0")
    if len(field) > 32:
        raise ValueError("serial too long")
    return field.encode("ascii")


# SPEC §3.2
def pc_code(cert, explicit):
    if explicit is not None:
        return explicit
    for attr in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME):
        match = re.fullmatch(r"CSPB-(\d{1,3})", attr.value)
        if match:
            return int(match.group(1))
    raise ValueError("PC code required")


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# SPEC §5 step 4, v2: odd parity on each byte of the 3DES key
def odd_parity(key):
    out = bytearray()
    for b in key:
        high = b & 0xFE
        out.append(high | (0 if bin(high).count("1") % 2 else 1))
    return bytes(out)


def zip_single(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("content", data)
    return buf.getvalue()


def seal(args):
    with open(args.input, "rb") as f:
        content = f.read()
    cert = load_cert(args.cert)
    key = load_key(args.key)
    to = load_cert(args.to) if args.to else None
    version, c04 = args.version, args.c04
    encrypted = c04 not in NOT_ENCRYPTED

    # 1. Compression
    data = content
    if c04 in COMPRESSED:
        data = gzip.compress(data, mtime=0) if args.compression == "gzip" else zip_single(data)

    # 2. Padding (v2 only)
    if version == 2 and len(data) % 8:
        data += b"\x00" * (8 - len(data) % 8)

    # 3. Signature over the padded content
    c15 = key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    # 4. Encryption
    if encrypted:
        recipient = to.public_key()
        if version == 3:
            k, n = os.urandom(32), os.urandom(12)
            body = AESGCM(k).encrypt(n, data, None)  # ciphertext || tag
            c14 = recipient.encrypt(k + n, padding.PKCS1v15())
        else:
            k = odd_parity(os.urandom(24))
            enc = Cipher(TripleDES(k), modes.CBC(k[:8])).encryptor()
            body = enc.update(data) + enc.finalize()
            c14 = recipient.encrypt(k, padding.PKCS1v15())
    else:
        body, c14 = data, b"\x00" * 256

    # 5. Header
    to_pc = pc_code(to, args.to_pc) if to else 0
    to_serial = serial_field(to) if to else b"\x00" * 32
    header = (
        struct.pack(">H", HEADER_SIZE)
        + bytes([version, 0, c04, 0, 2, 1 if version == 2 else 2, 2, 3, to_pc])
        + to_serial
        + bytes([pc_code(cert, args.pc)])
        + serial_field(cert)
        + c14
        + c15
    )
    assert len(header) == HEADER_SIZE

    with open(args.output, "wb") as f:
        f.write(header + body)


def gunzip_tolerant(data):
    out = b""
    while data:
        d = zlib.decompressobj(31)
        out += d.decompress(data)
        if not d.eof:
            raise ValueError("truncated gzip")
        data = d.unused_data
        if data.strip(b"\x00") == b"":
            break
    return out


def decompress(data):
    if data[:2] == b"\x1f\x8b":
        return gunzip_tolerant(data), "gzip"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if len(names) != 1:
                raise ValueError("zip must have one entry")
            return zf.read(names[0]), "zip"
    return data, "none"


# RFC 8017 §7.2.2: EM = 0x00 || 0x02 || PS (>= 8 non-zero bytes) || 0x00 || M
def rsaes_pkcs1_v15_decrypt(key, ciphertext):
    numbers = key.private_numbers()
    n, d = numbers.public_numbers.n, numbers.d
    k = (n.bit_length() + 7) // 8
    c = int.from_bytes(ciphertext, "big")
    if len(ciphertext) != k or c >= n:
        raise ValueError("decryption error")
    em = pow(c, d, n).to_bytes(k, "big")
    sep = em.find(b"\x00", 2)
    if em[0] != 0 or em[1] != 2 or sep < 10:
        raise ValueError("decryption error")
    return em[sep + 1:]


def open_envelope(args):
    with open(args.input, "rb") as f:
        envelope = f.read()
    cert = load_cert(args.cert)
    key = load_key(args.key)
    sender = load_cert(args.sender)

    # SPEC §6.2, phase A (lowest code wins)
    if len(envelope) < HEADER_SIZE or struct.unpack(">H", envelope[:2])[0] != HEADER_SIZE:
        raise EnvelopeError(0x01)
    h, body = envelope[:HEADER_SIZE], envelope[HEADER_SIZE:]
    c02, c03, c04, c05, c06, c07, c08, c09, c10 = h[2:11]
    c11, c12, c13 = h[11:43], h[43], h[44:76]
    c14, c15 = h[76:332], h[332:588]
    encrypted = c04 not in NOT_ENCRYPTED

    errors = []
    if c02 not in (2, 3):
        errors.append(0x02)
    if encrypted and c06 != 2:
        errors.append(0x03)
    if (c02, c07) not in ((2, 1), (3, 2)):
        errors.append(0x04)
    if c08 != 2:
        errors.append(0x05)
    if c09 != 3:
        errors.append(0x06)
    if encrypted and c10 != pc_code(cert, args.pc):
        errors.append(0x07)
    if encrypted and c11 != serial_field(cert):
        errors.append(0x08)
    if c13 == serial_field(sender) and c12 != pc_code(sender, args.from_pc):
        errors.append(0x09)
    if c13 != serial_field(sender):
        errors.append(0x0A)
    if c04 not in C04_VALUES:
        errors.append(0x13)
    if errors:
        raise EnvelopeError(min(errors))

    # Phase B
    if not encrypted:
        data = body
    elif c02 == 3:
        if len(body) < 16:
            raise EnvelopeError(0x0E)
        try:
            kn = rsaes_pkcs1_v15_decrypt(key, c14)
        except ValueError:
            raise EnvelopeError(0x0D)
        if len(kn) != 44:
            raise EnvelopeError(0x0D)
        try:
            data = AESGCM(kn[:32]).decrypt(kn[32:], body, None)
        except InvalidTag:
            raise EnvelopeError(0x0E)
    else:
        if len(body) % 8:
            raise EnvelopeError(0x0F)
        try:
            k = rsaes_pkcs1_v15_decrypt(key, c14)
        except ValueError:
            raise EnvelopeError(0x0D)
        if len(k) != 24:
            raise EnvelopeError(0x0D)
        dec = Cipher(TripleDES(k), modes.CBC(k[:8])).decryptor()
        data = dec.update(body) + dec.finalize()

    try:
        sender.public_key().verify(c15, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise EnvelopeError(0x0B)

    compression = "none"
    if c04 in COMPRESSED:
        try:
            data, compression = decompress(data)
        except Exception:
            raise EnvelopeError(0x12)

    with open(args.output, "wb") as f:
        f.write(data)
    return "ok c03=%d c04=%d compression=%s" % (c03, c04, compression)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("seal")
    s.add_argument("--cert", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--pc", type=int)
    s.add_argument("--to")
    s.add_argument("--to-pc", type=int)
    s.add_argument("--version", type=int, choices=(2, 3), required=True)
    s.add_argument("--c04", type=int, required=True)
    s.add_argument("--compression", choices=("gzip", "zip"))
    s.add_argument("input")
    s.add_argument("output")

    o = sub.add_parser("open")
    o.add_argument("--cert", required=True)
    o.add_argument("--key", required=True)
    o.add_argument("--pc", type=int)
    o.add_argument("--from", dest="sender", required=True)
    o.add_argument("--from-pc", type=int)
    o.add_argument("input")
    o.add_argument("output")

    args = parser.parse_args()
    if args.command == "seal":
        seal(args)
        return 0
    try:
        print(open_envelope(args))
        return 0
    except EnvelopeError as e:
        print("error %d" % e.code)
        return 1


if __name__ == "__main__":
    sys.exit(main())
