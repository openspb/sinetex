# Sinetex

The security envelope of the **RSFN** (Rede do Sistema Financeiro Nacional), the
network that connects Brazilian financial institutions, clearing houses and
Banco Central do Brasil, for Elixir.

It builds and opens the 588-byte security header defined in chapter 5 of the
public [*Manual de Segurança do SFN*][manual] (Volume I, version 6.00; chapter 5
is the same as in version 5.07), with **Security Protocol v3** (AES-256-GCM)
and **v2** (3DES, legacy): signing, encryption, compression and the C03 error
table. Newer versions of the manual are published on the
[Comunicação Eletrônica de Dados](https://www.bcb.gov.br/estabilidadefinanceira/comunicacaodados)
page of Banco Central.

[Leia em português](README.pt-BR.md).

> **Status: v0.1, pre-release.** The library follows the manual and is tested
> against an independent implementation, but a few points where the manual is
> silent follow observed market practice and have not been confirmed against
> real traffic yet. They are listed in [docs/SPEC.md](docs/SPEC.md#9-market-practice-items-to-confirm).
> Version 1.0 waits for that confirmation.
>
> Sinetex is an independent open source project. It is not affiliated with or
> endorsed by Banco Central do Brasil.

## Scope

**In:** the header (C01–C15), sending and receiving in v2 and v3, every C04
value, the error table with the "lowest code wins" rule, GZIP and ZIP.

**Out:** transport (MQ, Connect:Direct, SFTP), the XML of the messages,
certificate registration and activation, revocation lists, key storage. The
library works on bytes: you give it the content and the keys, it gives you the
envelope, and the other way round. It has no runtime dependencies besides
`:crypto` and `:public_key`.

## Installation

```elixir
def deps do
  [{:sinetex, "~> 0.1"}]
end
```

Elixir 1.16 or later, OTP 26 or later. Version 2 of the protocol needs 3DES in
the OpenSSL that OTP is linked to.

## Usage

### Keys and certificates

```elixir
# Your certificate and private key (PEM or DER; PKCS#1, PKCS#8 or encrypted PKCS#8)
{:ok, me} = Sinetex.Identity.load(File.read!("me.crt"), File.read!("me.key"))

# The counterparty's certificate
{:ok, peer} = Sinetex.Certificate.load(File.read!("peer.crt"))
```

C10 and C12 carry the code of the certification authority (PC). It is read
from `OU=CSPB-n` in the certificate issuer. For certificates without it, give
it explicitly: `Sinetex.Certificate.load(pem, pc: 4)`.

Certificates must be RSA-2048 with a serial number of at most 16 bytes, as the
header requires.

### Sending

```elixir
{:ok, envelope} = Sinetex.seal(xml, from: me, to: peer)

# A compressed file (C04 8). The format is required: see below.
{:ok, envelope} = Sinetex.seal(file, from: me, to: peer, c04: 8, compression: :gzip)

# Version 2
{:ok, envelope} = Sinetex.seal(xml, from: me, to: peer, version: 2)
```

### Receiving

```elixir
case Sinetex.open(envelope, as: me, from: peer) do
  {:ok, %Sinetex.Opened{content: content, header: header}} ->
    # header.c03 != 0 means the counterparty is reporting an error
    ...

  {:error, %Sinetex.Error{c03: c03, egen: egen} = error} ->
    # c03 is the code of the manual's table, egen the GEN0004 code (EGEN99xx)
    Logger.warning(Exception.message(error))
end
```

`:from` accepts a list of certificates, for a sender that is changing
certificates. Other options:

| Option | Default | |
|---|---|---|
| `:known` | `[]` | Other certificates. A message signed with one of them fails with `0x0C` (certificate does not belong to the sender) instead of `0x0A` |
| `:certificate_check` | none | `fn cert, header -> :ok \| {:error, c03} end`, for what depends on your certificate registry: not activated (`0x10`), expired or revoked (`0x11`), invalid (`0x14`) |
| `:c14_errors` | `:manual` | `:uniform` reports a failure to decrypt C14 as `0x0E` instead of `0x0D`. See [SECURITY.md](SECURITY.md) |
| `:trim_padding` | `false` | v2 keeps its `0x00` padding, as the manual says. `true` removes up to 7 trailing zeros |
| `:allow_clear` | `false` | Accept the "empty" header (all fields zero, e.g. a GEN0001 echo), whose body is neither signed nor encrypted |
| `:max_output_bytes` | 512 MiB | Limit for decompressed content |
| `:max_input_bytes` | `:infinity` | Limit for the envelope |

### Reporting an error

The library never answers anyone. When `open/2` fails, you decide whether to
send a GEN0004 back. `error_envelope/2` builds its envelope: signed, not
encrypted (C04 3), with C03 set. The GEN0004 XML is yours to build.

```elixir
with {:error, %Sinetex.Error{} = error} <- Sinetex.open(envelope, as: me, from: peer) do
  Sinetex.error_envelope(gen0004_xml(error.egen), from: me, to: peer, c03: error.c03)
end
```

### Compression

With C04 8 and 10, `:compression` is required when sending. The library has no
default because the right format depends on the destination: clearing houses
use GZIP, while the manual and the Bacen SFTP servers use ZIP with DEFLATE.

When receiving, the format is detected by its magic bytes, not by C04, and
`%Sinetex.Opened{compression: :gzip | :zip | :none}` tells which one was found.
Content marked as compressed that is not GZIP or ZIP is returned as is, which
has been observed in practice.

## Inspecting real traffic

`tools/header_dump.exs` prints the header of an envelope without decrypting
anything and without keys. It does not need the library:

```
elixir tools/header_dump.exs envelope.bin
```

## Documentation

* API documentation: `mix docs`, or [HexDocs](https://hexdocs.pm/sinetex) once published.
* [docs/SPEC.md](docs/SPEC.md): what the library does with each byte, with the
  source of every rule (manual, market practice or library decision).
* [guides/manual.md](guides/manual.md) (Portuguese): each function next to the
  section of the manual it implements.
* [SECURITY.md](SECURITY.md): security notes and how to report a vulnerability.

## Development

```
mix test
```

The test certificates and keys are generated by
`test/support/gen_fixtures.sh` (needs `openssl`) on the first run. No key or
sample from any third party is in the repository.

The interoperability tests run against an independent implementation in
Python, written from the specification only. They need Python 3 with the
`cryptography` package and are skipped without it:

```
python3 -m venv .venv && .venv/bin/pip install cryptography
SINETEX_PYTHON=.venv/bin/python mix test
```

## License

Apache-2.0: see the `LICENSE` and `NOTICE` files.

[manual]: https://www.bcb.gov.br/content/estabilidadefinanceira/cedsfn/Manual%20de%20Seguran%C3%A7a%20do%20SFN%20-%20Vol.I%20-%20v6_00.pdf
