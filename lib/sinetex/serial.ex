defmodule Sinetex.Serial do
  @moduledoc """
  Certificate serial numbers as written in fields C11 and C13
  (*Manual de Segurança do SFN* §5.1.4, §5.2.6).

  The serial number is written in upper-case hexadecimal, left-padded with
  the ASCII character `"0"` to 32 bytes.
  """

  @size 32

  @doc """
  Encodes a serial number into the 32-byte field format.

      iex> Sinetex.Serial.encode(0x5D77DA7B6F02EFA1EDDA741E78FF3508)
      {:ok, "5D77DA7B6F02EFA1EDDA741E78FF3508"}

      iex> Sinetex.Serial.encode(0x3B3BC056)
      {:ok, "0000000000000000000000003B3BC056"}

  Serial numbers longer than 16 bytes do not fit the field:

      iex> Sinetex.Serial.encode(0x0102030405060708090A0B0C0D0E0F1011)
      {:error, :serial_too_long}
  """
  @spec encode(integer()) :: {:ok, <<_::256>>} | {:error, :serial_too_long | :invalid_serial}
  def encode(serial) when is_integer(serial) and serial >= 0 do
    hex = Integer.to_string(serial, 16)

    if byte_size(hex) <= @size do
      {:ok, String.pad_leading(hex, @size, "0")}
    else
      {:error, :serial_too_long}
    end
  end

  def encode(serial) when is_integer(serial), do: {:error, :invalid_serial}

  @doc """
  Returns `true` if `field` is a well-formed C11/C13 value: 32 bytes, each one
  of `0-9` or `A-F`.

      iex> Sinetex.Serial.valid?("0000000000000000000000003B3BC056")
      true

      iex> Sinetex.Serial.valid?("0000000000000000000000003b3bc056")
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(<<field::binary-size(@size)>>), do: hex_upper?(field)
  def valid?(_), do: false

  defp hex_upper?(<<c, rest::binary>>) when c in ?0..?9 or c in ?A..?F, do: hex_upper?(rest)
  defp hex_upper?(<<>>), do: true
  defp hex_upper?(_), do: false
end
