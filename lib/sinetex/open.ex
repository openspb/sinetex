defmodule Sinetex.Open do
  @moduledoc false

  # Receiving side (§5.3) and error reporting (§5.5).
  #
  # Phase A checks the header and reports the lowest error code found
  # (§5.5.3). Phase B runs the cryptography in order and stops at the first
  # error.

  alias Sinetex.{Certificate, Compression, Crypto, Error, Header, Identity, Opened, Serial}

  @c04_values [0, 1, 2, 3, 4, 6, 8, 10]
  @not_encrypted [2, 3, 6, 10]
  @compressed [8, 10]

  @default_max_output 512 * 1024 * 1024

  @spec open(binary(), keyword()) :: {:ok, Opened.t()} | {:error, Error.t()}
  def open(envelope, opts) when is_binary(envelope) and is_list(opts) do
    opts =
      Keyword.validate!(opts, [
        :as,
        :from,
        certificate_check: nil,
        known: [],
        c14_errors: :manual,
        trim_padding: false,
        allow_clear: false,
        max_input_bytes: :infinity,
        max_output_bytes: @default_max_output
      ])

    import Sinetex.Seal, only: [validate!: 4]

    me = validate!(opts, :as, &match?(%Identity{}, &1), "a Sinetex.Identity")

    senders =
      validate!(
        opts,
        :from,
        &certificates?(&1, 1),
        "a Sinetex.Certificate or a non-empty list of them"
      )

    known = validate!(opts, :known, &certificates?(&1, 0), "a list of Sinetex.Certificate")
    validate!(opts, :certificate_check, &(is_nil(&1) or is_function(&1, 2)), "a 2-arity function")
    validate!(opts, :c14_errors, &(&1 in [:manual, :uniform]), ":manual or :uniform")
    validate!(opts, :trim_padding, &is_boolean/1, "a boolean")
    validate!(opts, :allow_clear, &is_boolean/1, "a boolean")

    validate!(
      opts,
      :max_input_bytes,
      &(&1 == :infinity or (is_integer(&1) and &1 > 0)),
      "a positive integer or :infinity"
    )

    validate!(opts, :max_output_bytes, &(is_integer(&1) and &1 > 0), "a positive integer")

    ctx = %{
      me: me,
      senders: List.wrap(senders),
      known: known,
      opts: Map.new(opts)
    }

    do_open(envelope, ctx)
  end

  defp certificates?(%Certificate{}, _min), do: true

  defp certificates?(list, min) when is_list(list),
    do: length(list) >= min and Enum.all?(list, &match?(%Certificate{}, &1))

  defp certificates?(_, _min), do: false

  defp do_open(envelope, ctx) do
    with :ok <- check_input_size(envelope, ctx.opts.max_input_bytes),
         {:ok, header, body} <- decode(envelope) do
      if Header.empty?(header) do
        open_clear(header, body, ctx)
      else
        open_protected(header, body, ctx)
      end
    end
  end

  defp check_input_size(_envelope, :infinity), do: :ok
  defp check_input_size(envelope, max) when byte_size(envelope) <= max, do: :ok
  defp check_input_size(_envelope, _max), do: error(0x12, :input_too_large)

  defp decode(envelope) do
    case Header.decode(envelope) do
      {:ok, %Header{c01: 588} = header, body} -> {:ok, header, body}
      {:ok, %Header{c01: c01}, _body} -> error(0x01, {:c01, c01})
      {:error, :too_short} -> error(0x01, {:too_short, byte_size(envelope)})
    end
  end

  # §5.6.3: every field zeroed except C01; the body is in clear text.
  defp open_clear(header, body, %{opts: %{allow_clear: true}}) do
    {:ok,
     %Opened{content: body, header: header, sender: nil, protection: :clear, compression: :none}}
  end

  defp open_clear(_header, _body, _ctx), do: error(0x02, :clear_not_allowed)

  defp open_protected(header, body, ctx) do
    with {:ok, sender} <- check_header(header, ctx),
         {:ok, data} <- recover(header, body, sender, ctx),
         {:ok, content, compression} <- finish(header, data, ctx) do
      {:ok,
       %Opened{
         content: content,
         header: header,
         sender: sender,
         protection: if(header.c04 in @not_encrypted, do: :signed, else: :signed_and_encrypted),
         compression: compression
       }}
    end
  end

  ## Phase A: header consistency (§5.3, §5.5.1, §5.5.3)

  defp check_header(h, ctx) do
    mine = ctx.me.certificate
    # C06, C10 and C11 only matter when the content is encrypted. An unknown
    # C04 counts as encrypted.
    encrypted? = h.c04 not in @not_encrypted
    {sender, sender_codes} = find_sender(h, ctx.senders, ctx.known)

    codes =
      [
        {h.c02 not in [2, 3], 0x02},
        {encrypted? and h.c06 != 0x02, 0x03},
        {not c07_ok?(h.c02, h.c07), 0x04},
        {h.c08 != 0x02, 0x05},
        {h.c09 != 0x03, 0x06},
        {encrypted? and h.c10 != mine.pc, 0x07},
        {encrypted? and h.c11 != mine.serial_field, 0x08},
        {h.c04 not in @c04_values, 0x13}
      ]
      |> Enum.flat_map(fn
        {true, code} -> [code]
        {false, _} -> []
      end)

    codes = codes ++ sender_codes ++ certificate_check(sender, h, ctx.opts.certificate_check)

    case codes do
      [] -> {:ok, sender}
      codes -> error(Enum.min(codes), {:header, codes |> Enum.uniq() |> Enum.sort()})
    end
  end

  # v2 goes with 3DES, v3 with AES-256. With an invalid version, only the
  # value itself is checked.
  defp c07_ok?(2, c07), do: c07 == 0x01
  defp c07_ok?(3, c07), do: c07 == 0x02
  defp c07_ok?(_, c07), do: c07 in [0x01, 0x02]

  # The sender certificate is found by C13 (serial) and C12 (PC).
  #   - exact match among the expected senders: ok;
  #   - exact match among the other known certificates: 0x0C;
  #   - serial matches, PC does not: 0x09;
  #   - nothing matches: 0x0A.
  defp find_sender(h, senders, known) do
    if Serial.valid?(h.c13) do
      by_serial = fn certs -> Enum.filter(certs, &(&1.serial_field == h.c13)) end
      exact = fn certs -> Enum.find(certs, &(&1.pc == h.c12)) end
      {from_serial, known_serial} = {by_serial.(senders), by_serial.(known)}

      cond do
        sender = exact.(from_serial) -> {sender, []}
        exact.(known_serial) -> {nil, [0x0C]}
        from_serial != [] or known_serial != [] -> {nil, [0x09]}
        true -> {nil, [0x0A | c12_zero(h)]}
      end
    else
      {nil, [0x0A | c12_zero(h)]}
    end
  end

  defp c12_zero(%Header{c12: 0}), do: [0x09]
  defp c12_zero(_), do: []

  defp certificate_check(nil, _header, _fun), do: []
  defp certificate_check(_sender, _header, nil), do: []

  defp certificate_check(sender, header, fun) do
    case fun.(sender, header) do
      :ok ->
        []

      {:error, code} when is_integer(code) ->
        if Error.code?(code), do: [code], else: bad_check!({:error, code})

      other ->
        bad_check!(other)
    end
  end

  @spec bad_check!(term()) :: no_return()
  defp bad_check!(result) do
    raise ArgumentError,
          "expected :certificate_check to return :ok or {:error, c03_code}, got: #{inspect(result)}"
  end

  ## Phase B: cryptography (§5.3.3 - §5.3.6)

  defp recover(%Header{c04: c04} = h, body, sender, _ctx) when c04 in @not_encrypted do
    verify(body, h, sender)
  end

  defp recover(%Header{c02: 3}, body, _sender, _ctx) when byte_size(body) < 16 do
    error(0x0E, :body_too_short)
  end

  defp recover(%Header{c02: 3} = h, body, sender, ctx) do
    case Crypto.unwrap_key(h.c14, ctx.me.private_key, 44) do
      {:ok, <<key::binary-32, nonce::binary-12>>} ->
        with {:ok, data} <- aes_gcm_decrypt(key, nonce, body), do: verify(data, h, sender)

      {:error, reason, <<key::binary-32, nonce::binary-12>>} ->
        # Same work as with a good key: decrypt the body and fail.
        _ = Crypto.aes_gcm_decrypt(key, nonce, body)
        c14_error(reason, ctx)
    end
  end

  defp recover(%Header{c02: 2}, body, _sender, _ctx) when rem(byte_size(body), 8) != 0 do
    error(0x0F, {:body_size, byte_size(body)})
  end

  defp recover(%Header{c02: 2} = h, body, sender, ctx) do
    if Crypto.des3_available?(),
      do: recover_v2(h, body, sender, ctx),
      else: error(0x12, :des3_unavailable)
  end

  defp recover_v2(h, body, sender, ctx) do
    case Crypto.unwrap_key(h.c14, ctx.me.private_key, 24) do
      {:ok, key} ->
        with {:ok, data} <- des3_decrypt(key, body), do: verify(data, h, sender)

      {:error, reason, key} ->
        # v2 has no integrity check before the signature, so also verify
        # it, as with a good key.
        _ = with {:ok, data} <- des3_decrypt(key, body), do: verify(data, h, sender)
        c14_error(reason, ctx)
    end
  end

  defp aes_gcm_decrypt(key, nonce, body) do
    with :error <- Crypto.aes_gcm_decrypt(key, nonce, body), do: error(0x0E, :gcm_tag_mismatch)
  end

  defp des3_decrypt(key, body) do
    with :error <- Crypto.des3_decrypt(key, body), do: error(0x0E, :des3_failed)
  end

  defp verify(data, h, sender) do
    if Crypto.verify?(data, h.c15, sender.public_key) do
      {:ok, data}
    else
      error(0x0B, :bad_signature)
    end
  end

  defp c14_error(reason, %{opts: %{c14_errors: :manual}}), do: error(0x0D, {:c14, reason})
  defp c14_error(reason, %{opts: %{c14_errors: :uniform}}), do: error(0x0E, {:c14, reason})

  ## After the signature: decompression and padding

  defp finish(%Header{c04: c04} = h, data, ctx) when c04 in @compressed do
    case Compression.decompress(data, ctx.opts.max_output_bytes) do
      {:ok, content, :none} -> {:ok, trim(content, h, ctx), :none}
      {:ok, content, format} -> {:ok, content, format}
      {:error, reason} -> error(0x12, {:decompression, reason})
    end
  end

  defp finish(h, data, ctx), do: {:ok, trim(data, h, ctx), :none}

  # v2 padding stays by default (§5.7.14); trim_padding: true removes up to
  # 7 trailing 0x00 bytes.
  defp trim(data, %Header{c02: 2}, %{opts: %{trim_padding: true}}) do
    zeros = count_trailing_zeros(data, byte_size(data) - 1, 0)
    binary_part(data, 0, byte_size(data) - zeros)
  end

  defp trim(data, _header, _ctx), do: data

  defp count_trailing_zeros(_data, _pos, 7), do: 7
  defp count_trailing_zeros(_data, pos, n) when pos < 0, do: n

  defp count_trailing_zeros(data, pos, n) do
    if :binary.at(data, pos) == 0, do: count_trailing_zeros(data, pos - 1, n + 1), else: n
  end

  defp error(code, reason), do: {:error, Error.new(code, reason)}
end
