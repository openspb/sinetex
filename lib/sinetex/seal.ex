defmodule Sinetex.Seal do
  @moduledoc false

  # Sending side (§5.2): compress -> pad -> sign -> encrypt -> header.

  alias Sinetex.{Certificate, Compression, Crypto, Header, Identity, Random}

  @c04_values [0, 1, 2, 3, 4, 6, 8, 10]
  @encrypted [0, 1, 4, 8]
  @compressed [8, 10]

  @spec seal(binary(), keyword(), 0..255) :: {:ok, binary()} | {:error, atom()}
  def seal(content, opts, c03 \\ 0) when is_binary(content) and is_list(opts) do
    opts = validate_options!(opts)
    %{from: from, to: to, version: version, c04: c04, compression: compression} = Map.new(opts)

    encrypted? = c04 in @encrypted

    with :ok <- ensure(to != nil or not encrypted?, :recipient_required),
         :ok <- ensure(version == 3 or Crypto.des3_available?(), :des3_unavailable),
         {:ok, data} <- compress(content, c04, compression, opts) do
      data = pad(data, version)
      c15 = Crypto.sign(data, from.private_key)
      {c14, body} = if encrypted?, do: encrypt(version, data, to), else: {<<0::2048>>, data}

      header = %Header{
        c02: version,
        c03: c03,
        c04: c04,
        c06: 0x02,
        c07: if(version == 2, do: 0x01, else: 0x02),
        c08: 0x02,
        c09: 0x03,
        c10: if(to, do: to.pc, else: 0),
        c11: if(to, do: to.serial_field, else: <<0::256>>),
        c12: from.certificate.pc,
        c13: from.certificate.serial_field,
        c14: c14,
        c15: c15
      }

      {:ok, Header.encode(header) <> body}
    end
  end

  defp validate_options!(opts) do
    opts =
      Keyword.validate!(opts, [
        :from,
        to: nil,
        compression: nil,
        version: 3,
        c04: 0,
        zip_entry_name: "content"
      ])

    validate!(opts, :from, &match?(%Identity{}, &1), "a Sinetex.Identity")
    validate!(opts, :to, &(is_nil(&1) or match?(%Certificate{}, &1)), "a Sinetex.Certificate")
    validate!(opts, :version, &(&1 in [2, 3]), "2 or 3")
    validate!(opts, :c04, &(&1 in @c04_values), "one of #{inspect(@c04_values)}")
    validate!(opts, :compression, &(&1 in [nil, :gzip, :zip]), ":gzip or :zip")

    validate!(
      opts,
      :zip_entry_name,
      &(is_binary(&1) and byte_size(&1) in 1..0xFFFF),
      "a non-empty binary"
    )

    if opts[:compression] && opts[:c04] not in @compressed do
      raise ArgumentError,
            "the :compression option only applies to c04 8 or 10, got c04: #{opts[:c04]}"
    end

    opts
  end

  defp compress(_content, c04, nil, _opts) when c04 in @compressed,
    do: {:error, :compression_required}

  defp compress(content, c04, format, opts) when c04 in @compressed,
    do: Compression.compress(content, format, opts)

  defp compress(content, _c04, _format, _opts), do: {:ok, content}

  # v2: 0x00 up to a multiple of 8 (§5.2.3, §5.7.14). v3: no padding.
  defp pad(data, 2) do
    case rem(byte_size(data), 8) do
      0 -> data
      r -> data <> :binary.copy(<<0>>, 8 - r)
    end
  end

  defp pad(data, 3), do: data

  defp encrypt(3, data, to) do
    key = Random.bytes(32)
    nonce = Random.bytes(12)
    {Crypto.wrap_key(key <> nonce, to.public_key), Crypto.aes_gcm_encrypt(key, nonce, data)}
  end

  defp encrypt(2, data, to) do
    key = Crypto.odd_parity(Random.bytes(24))
    {Crypto.wrap_key(key, to.public_key), Crypto.des3_encrypt(key, data)}
  end

  defp ensure(true, _reason), do: :ok
  defp ensure(false, reason), do: {:error, reason}

  @doc false
  @spec validate!(keyword(), atom(), (term() -> boolean()), String.t()) :: term()
  def validate!(opts, key, valid?, expected) do
    value = opts[key]

    if valid?.(value) do
      value
    else
      raise ArgumentError, "expected #{inspect(key)} to be #{expected}, got: #{inspect(value)}"
    end
  end
end
