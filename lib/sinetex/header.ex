defmodule Sinetex.Header do
  @moduledoc """
  The 588-byte security header (*Manual de Segurança do SFN* §5.1, Table 1).

  Field names follow the manual:

  | Field | Size | Content |
  |---|---:|---|
  | `c01` | 2 | header size, always 588 |
  | `c02` | 1 | protocol version (`0x02`, `0x03`; `0x00` for clear text) |
  | `c03` | 1 | error code, `0x00` when there is no error |
  | `c04` | 1 | special treatment indicator |
  | `c05` | 1 | reserved, `0x00` |
  | `c06` | 1 | recipient key algorithm (`0x02` = RSA-2048) |
  | `c07` | 1 | symmetric algorithm (`0x01` = 3DES, `0x02` = AES-256) |
  | `c08` | 1 | sender key algorithm (`0x02` = RSA-2048) |
  | `c09` | 1 | hash algorithm (`0x03` = SHA-256) |
  | `c10` | 1 | certification authority (PC) of the recipient certificate |
  | `c11` | 32 | serial number of the recipient certificate (`Sinetex.Serial`) |
  | `c12` | 1 | certification authority (PC) of the sender certificate |
  | `c13` | 32 | serial number of the sender certificate |
  | `c14` | 256 | symmetric key encrypted with RSAES-PKCS1-v1_5 |
  | `c15` | 256 | signature, RSASSA-PKCS1-v1_5 |

  `c01` is read and written as a big-endian 16-bit integer.

  The header is **not** covered by the signature: the protocol only signs the
  content. `Sinetex.open/2` checks every field against the certificates
  involved, but bytes such as C03, C04 and C05 can be changed in transit
  without breaking the signature.
  """

  @size 588

  defstruct c01: @size,
            c02: 0,
            c03: 0,
            c04: 0,
            c05: 0,
            c06: 0,
            c07: 0,
            c08: 0,
            c09: 0,
            c10: 0,
            c11: <<0::256>>,
            c12: 0,
            c13: <<0::256>>,
            c14: <<0::2048>>,
            c15: <<0::2048>>

  @type t :: %__MODULE__{
          c01: 0..0xFFFF,
          c02: byte(),
          c03: byte(),
          c04: byte(),
          c05: byte(),
          c06: byte(),
          c07: byte(),
          c08: byte(),
          c09: byte(),
          c10: byte(),
          c11: <<_::256>>,
          c12: byte(),
          c13: <<_::256>>,
          c14: <<_::2048>>,
          c15: <<_::2048>>
        }

  @doc "The header size in bytes: 588."
  @spec size() :: 588
  def size, do: @size

  @doc """
  Encodes a header into its 588 bytes.

  Raises `ArgumentError` if a field does not fit its size.
  """
  @spec encode(t()) :: <<_::4704>>
  def encode(%__MODULE__{} = h) do
    unless valid_fields?(h) do
      raise ArgumentError, "header field out of range: #{inspect(h)}"
    end

    <<h.c01::16, h.c02, h.c03, h.c04, h.c05, h.c06, h.c07, h.c08, h.c09, h.c10,
      h.c11::binary-size(32), h.c12, h.c13::binary-size(32), h.c14::binary-size(256),
      h.c15::binary-size(256)>>
  end

  @byte_fields [:c02, :c03, :c04, :c05, :c06, :c07, :c08, :c09, :c10, :c12]

  defp valid_fields?(h) do
    h.c01 in 0..0xFFFF and Enum.all?(@byte_fields, &(Map.fetch!(h, &1) in 0..255)) and
      sized?(h.c11, 32) and sized?(h.c13, 32) and sized?(h.c14, 256) and sized?(h.c15, 256)
  end

  defp sized?(bin, size), do: is_binary(bin) and byte_size(bin) == size

  @doc """
  Splits an envelope into its header and body.

  Only the layout is decoded; field values are not validated. Returns
  `{:error, :too_short}` if there are fewer than 588 bytes.
  """
  @spec decode(binary()) :: {:ok, t(), body :: binary()} | {:error, :too_short}
  def decode(
        <<c01::16, c02, c03, c04, c05, c06, c07, c08, c09, c10, c11::binary-size(32), c12,
          c13::binary-size(32), c14::binary-size(256), c15::binary-size(256), body::binary>>
      ) do
    header = %__MODULE__{
      c01: c01,
      c02: c02,
      c03: c03,
      c04: c04,
      c05: c05,
      c06: c06,
      c07: c07,
      c08: c08,
      c09: c09,
      c10: c10,
      c11: c11,
      c12: c12,
      c13: c13,
      c14: c14,
      c15: c15
    }

    {:ok, header, body}
  end

  def decode(envelope) when is_binary(envelope), do: {:error, :too_short}

  @doc """
  Returns `true` for the "empty" header of §5.6.3: every field zeroed except
  C01. The body of such an envelope is in clear text, neither signed nor
  encrypted.
  """
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{} = header), do: header == %__MODULE__{c01: header.c01}

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(header, opts) do
      fields =
        header
        |> Map.from_struct()
        |> Enum.sort()
        |> Enum.map(fn
          {k, v} when k in [:c14, :c15] -> {k, summary(v)}
          {k, v} when is_integer(v) and k != :c01 -> {k, hex(v)}
          other -> other
        end)

      container_doc("#Sinetex.Header<", fields, ">", opts, &field/2,
        separator: ",",
        break: :strict
      )
    end

    defp field({k, v}, _opts) when is_atom(v), do: concat([Atom.to_string(k), ": ", to_string(v)])
    defp field({k, v}, opts), do: concat([Atom.to_string(k), ": ", to_doc(v, opts)])

    defp summary(<<0::2048>>), do: :zero
    defp summary(_), do: :"256 bytes"

    defp hex(v), do: :"0x#{v |> Integer.to_string(16) |> String.pad_leading(2, "0")}"
  end
end
