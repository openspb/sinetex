defmodule Sinetex do
  @moduledoc """
  The security envelope of the RSFN, the network of the Brazilian Financial
  System, as defined in chapter 5 of the *Manual de Segurança do SFN*
  published by Banco Central do Brasil. Section numbers such as §5.5.3 refer
  to that manual (version 5.07; Volume I of version 6.00 keeps the same
  chapter 5).

  An envelope is a 588-byte header (`Sinetex.Header`) followed by the body:

    * **Security Protocol v3**: AES-256-GCM, RSA-2048, SHA-256;
    * **Security Protocol v2** (legacy): 3DES-EDE3-CBC, RSA-2048, SHA-256.

  The library works on bytes. It does not parse the XML of the message, does
  not talk to the network and does not store keys.

  ## Example

      {:ok, me} = Sinetex.Identity.load(File.read!("me.pem"), File.read!("me.key"))
      {:ok, peer} = Sinetex.Certificate.load(File.read!("peer.pem"))

      # Sending
      {:ok, envelope} = Sinetex.seal(xml, from: me, to: peer)

      # Receiving
      {:ok, %Sinetex.Opened{content: xml}} = Sinetex.open(incoming, as: me, from: peer)

  ## Special treatment (C04)

  | C04 | Meaning | Compressed | Encrypted |
  |---:|---|:-:|:-:|
  | 0 | message or file, signed and encrypted (default) | | ✔ |
  | 1 | uses a certificate that is not activated yet (GEN0006) | | ✔ |
  | 2 | public broadcast, no recipient | | |
  | 3 | security message, e.g. GEN0004 (see `error_envelope/2`) | | |
  | 4 | file, not compressed | | ✔ |
  | 6 | file, not compressed, public | | |
  | 8 | file, compressed | ✔ | ✔ |
  | 10 | file, compressed, public | ✔ | |

  Every value is signed. That 1 and 4 are encrypted is market practice, not
  stated by the manual.

  ## Errors

  `open/2` returns `{:error, %Sinetex.Error{}}` with the C03 code of the
  manual's error table. When there is more than one error in the header, the
  lowest code is reported (§5.5.3). Malformed input never raises.
  """

  alias Sinetex.{Error, Opened}

  @doc """
  Builds an envelope: compresses (C04 8 and 10), pads (v2), signs and
  encrypts `content`.

  ## Options

    * `:from` (required) - your `Sinetex.Identity`; signs the content.
    * `:to` - the recipient's `Sinetex.Certificate`. Required when C04
      means encrypted; optional otherwise (when given, it fills C10/C11).
    * `:version` - `3` (default) or `2`. Version 2 is legacy and needs 3DES
      in the host OpenSSL, which FIPS mode may disable.
    * `:c04` - special treatment indicator, default `0`. See the table in
      the module documentation.
    * `:compression` - `:gzip` or `:zip`. **Required** with C04 8 and 10 and
      not accepted otherwise. There is no default because the right format
      depends on the destination: clearing houses use GZIP, the manual
      describes ZIP (and the Bacen SFTP servers use ZIP with DEFLATE).
    * `:compression_level` - `:default`, `:none`, `:best_speed`,
      `:best_compression` or an integer in `0..9`, as in `:zlib`. Only with
      `:compression`. Without it the output is the same as with `:default`.
      `:best_speed` is faster and compresses less.
    * `:zip_entry_name` - name of the single ZIP entry, default `"content"`.

  ## Errors

    * `{:error, :compression_required}` - C04 8 or 10 without `:compression`;
    * `{:error, :recipient_required}` - encrypted C04 without `:to`;
    * `{:error, :des3_unavailable}` - version 2 and no 3DES in OpenSSL;
    * `{:error, :zip64_unsupported}` - ZIP content of 4 GiB or more.

  Invalid options raise `ArgumentError`.
  """
  @spec seal(binary(), keyword()) ::
          {:ok, binary()}
          | {:error,
             :compression_required | :recipient_required | :des3_unavailable | :zip64_unsupported}
  def seal(content, opts), do: Sinetex.Seal.seal(content, opts)

  @doc """
  Opens an envelope: checks the header, decrypts, verifies the signature
  and, for C04 8 and 10, decompresses.

  ## Options

    * `:as` (required) - your `Sinetex.Identity`; decrypts C14.
    * `:from` (required) - the expected sender: a `Sinetex.Certificate` or a
      list of them. The certificate is picked by C13 and C12 (see
      `:pc_check`).
    * `:known` - other certificates you know, default `[]`. A message signed
      with one of them is rejected with `0x0C` ("certificate does not belong
      to the sender") instead of `0x0A`.
    * `:certificate_check` - `fn certificate, header -> :ok | {:error, c03} end`,
      called with the sender certificate. Use it for what depends on the
      certificate registry: not activated (`0x10`), expired or revoked
      (`0x11`), invalid (`0x14`). C04 1 means the sender uses a certificate
      that is not activated yet; the header is passed so you can allow it.
    * `:c14_errors` - `:manual` (default) reports a failure to decrypt C14
      as `0x0D`, as the manual says. `:uniform` reports it as `0x0E`, the
      same as a failure in the body, so the error code is not a padding
      oracle. See `SECURITY.md`.
    * `:trim_padding` - v2 only. The manual says the padding is not removed
      (§5.7.14), so by default the content comes back as signed, with its
      trailing `0x00`. `true` removes up to 7 trailing `0x00` bytes, which
      also removes legitimate zeros at the end of the content.
    * `:allow_clear` - accept the "empty" header of §5.6.3 (GEN0001 echo),
      whose body is neither signed nor encrypted. Default `false`: such an
      envelope is rejected with `0x02`.
    * `:pc_check` - `:strict` (default) checks C10 against the PC of your
      certificate (`0x07`) and picks the sender by C13 and C12. `:ignore`
      skips the C10 check and picks the sender by C13 alone, for
      counterparties that do not fill C10/C12 with the PCs of the
      certificates. C12 then only breaks a tie between expected senders with
      the same serial number; if it cannot, the error is `0x09`. The
      signature is verified the same way in both modes.
    * `:max_output_bytes` - limit for decompressed content, default 512 MiB.
    * `:max_input_bytes` - limit for the envelope, default `:infinity`.

  ## Return

  `{:ok, %Sinetex.Opened{}}` or `{:error, %Sinetex.Error{}}`.

  An envelope whose C03 is not `0x00` is a counterparty reporting an error;
  it is opened like any other and the code is in `opened.header.c03`. Do not
  answer it with another error (§5.5.5).

  Invalid options raise `ArgumentError`.
  """
  @spec open(binary(), keyword()) :: {:ok, Opened.t()} | {:error, Error.t()}
  def open(envelope, opts), do: Sinetex.Open.open(envelope, opts)

  @doc """
  Builds the envelope that reports a security error to a counterparty
  (§5.5.2, §5.5.4, §5.5.7): signed, not encrypted (C04 3), with C03 set.

  `content` is the GEN0004 message, which the caller builds.

  ## Options

    * `:c03` (required) - the error code, usually `error.c03` from `open/2`.
    * `:from`, `:to`, `:version` - as in `seal/2`.

  ## Example

      with {:error, %Sinetex.Error{} = error} <- Sinetex.open(envelope, opts) do
        gen0004 = build_gen0004(error.egen)
        Sinetex.error_envelope(gen0004, from: me, to: peer, c03: error.c03)
      end
  """
  @spec error_envelope(binary(), keyword()) :: {:ok, binary()} | {:error, :des3_unavailable}
  def error_envelope(content, opts) when is_binary(content) and is_list(opts) do
    {c03, opts} = Keyword.pop(opts, :c03)

    unless Error.code?(c03) do
      raise ArgumentError, "expected :c03 to be a C03 error code, got: #{inspect(c03)}"
    end

    if Keyword.has_key?(opts, :c04) or Keyword.has_key?(opts, :compression) do
      raise ArgumentError, "error_envelope/2 always uses c04: 3, without compression"
    end

    Sinetex.Seal.seal(content, Keyword.put(opts, :c04, 3), c03)
  end
end
