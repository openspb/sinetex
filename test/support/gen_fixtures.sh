#!/usr/bin/env bash
#
# Generates the test-only PKI used by the sinetex test suite.
#
# Every key and certificate here is created by this script. None of them is,
# or derives from, a real RSFN certificate. Output goes to
# test/fixtures/generated/ (git-ignored); run again to regenerate.
#
# Requires OpenSSL 1.1.1 or newer.

set -euo pipefail

out="${1:-$(cd "$(dirname "$0")/.." && pwd)/fixtures/generated}"
rm -rf "$out"
mkdir -p "$out"
cd "$out"

days=3650

cat > ext.cnf <<'EOF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

# rsa_key NAME [BITS] [PUBLIC_EXPONENT]
rsa_key() {
  local args=(-algorithm RSA -pkeyopt "rsa_keygen_bits:${2:-2048}")
  if [ -n "${3:-}" ]; then args+=(-pkeyopt "rsa_keygen_pubexp:$3"); fi
  openssl genpkey "${args[@]}" -out "$1.key" 2>/dev/null
}

# ca NAME SUBJECT
ca() {
  rsa_key "$1"
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -signkey "$1.key" -sha256 -days "$days" \
    -set_serial 1 -extfile ext.cnf -extensions ca -out "$1.crt" 2>/dev/null
}

# leaf NAME CA SERIAL SUBJECT  (the key NAME.key must exist)
leaf() {
  openssl req -new -key "$1.key" -subj "$4" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -set_serial "$3" \
    -sha256 -days "$days" -extfile ext.cnf -extensions leaf -out "$1.crt" 2>/dev/null
}

# A CA in the SPB style: its subject (the issuer of the leaves) carries OU=CSPB-6.
ca ca_spb "/C=BR/O=Sinetex Test PKI/OU=CSPB-6/CN=Sinetex Test CA SPB"

# A CA outside the SPB style: no OU=CSPB-n.
ca ca_other "/C=BR/O=Sinetex Test PKI/CN=Sinetex Test CA Other"

# The serials of bank_a and bank_b are the examples given in the manual.
rsa_key bank_a
leaf bank_a ca_spb 0x5D77DA7B6F02EFA1EDDA741E78FF3508 "/C=BR/O=Bank A/CN=bank-a.test"

rsa_key bank_b
leaf bank_b ca_spb 0x3B3BC056 "/C=BR/O=Bank B/CN=bank-b.test"

rsa_key bank_c
leaf bank_c ca_spb 0x0C0C0C0C0C0C "/C=BR/O=Bank C/CN=bank-c.test"

# Issued by the non-SPB CA: loading it requires an explicit pc: option.
rsa_key chamber
leaf chamber ca_other 0x1234 "/C=BR/O=Test Chamber/CN=chamber.test"

# Same serial as bank_b, different CA (so a different PC once configured).
rsa_key twin_b
leaf twin_b ca_other 0x3B3BC056 "/C=BR/O=Twin B/CN=twin-b.test"

# 17-byte serial: does not fit C11/C13.
rsa_key long_serial
leaf long_serial ca_spb 0x0102030405060708090A0B0C0D0E0F1011 "/C=BR/O=Long Serial/CN=long.test"

# Keys the library must refuse.
rsa_key e3 2048 3
leaf e3 ca_spb 0x0E03 "/C=BR/O=Exponent Three/CN=e3.test"

rsa_key rsa1024 1024
leaf rsa1024 ca_spb 0x1024 "/C=BR/O=Small Key/CN=rsa1024.test"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key 2>/dev/null
leaf ec ca_spb 0x0EC0 "/C=BR/O=Elliptic/CN=ec.test"

# Other encodings of bank_a.
openssl x509 -in bank_a.crt -outform DER -out bank_a.crt.der
openssl pkey -in bank_a.key -outform DER -out bank_a.pkcs8.der
openssl rsa -in bank_a.key -traditional -out bank_a.pkcs1.pem 2>/dev/null
openssl rsa -in bank_a.key -traditional -outform DER -out bank_a.pkcs1.der 2>/dev/null
openssl pkey -in bank_a.key -aes256 -passout pass:test-password -out bank_a.encrypted.key

# A PKCS#12 file, turned into PEM with the commands of guides/manual.md.
openssl pkcs12 -export -in bank_a.crt -inkey bank_a.key -passout pass:test-password \
  -out bank_a.p12
openssl pkcs12 -in bank_a.p12 -passin pass:test-password -clcerts -nokeys \
  -out bank_a.from_p12.crt
openssl pkcs12 -in bank_a.p12 -passin pass:test-password -nocerts \
  -passout pass:test-password -out bank_a.from_p12.key

rm -f ./*.csr ./*.srl ext.cnf
touch .complete
