defmodule Sinetex.Compression do
  @moduledoc false

  # GZIP (RFC 1952) and single-entry ZIP, for C04 8 and 10.
  #
  # On read, the format comes from the magic bytes, not from C04, and the
  # reader tolerates the 0x00 padding that v2 leaves after the data. Output is
  # capped against decompression bombs.

  import Bitwise

  @type format :: :gzip | :zip

  @spec detect(binary()) :: format() | :none
  def detect(<<0x1F, 0x8B, _::binary>>), do: :gzip
  def detect(<<"PK", 3, 4, _::binary>>), do: :zip
  def detect(<<"PK", 5, 6, _::binary>>), do: :zip
  def detect(<<"PK", 7, 8, _::binary>>), do: :zip
  def detect(_), do: :none

  ## Compression

  @spec compress(binary(), format(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def compress(data, :gzip, _opts), do: {:ok, :zlib.gzip(data)}

  def compress(data, :zip, opts) when byte_size(data) < 0xFFFFFFFF do
    name = Keyword.fetch!(opts, :zip_entry_name)
    crc = :erlang.crc32(data)
    compressed = deflate_raw(data)
    # 1980-01-01 00:00, so that the output does not depend on the clock.
    {time, date} = {0, 0x21}
    # Bit 11: the name is UTF-8.
    flags = 0x0800

    local =
      <<0x04034B50::little-32, 20::little-16, flags::little-16, 8::little-16, time::little-16,
        date::little-16, crc::little-32, byte_size(compressed)::little-32,
        byte_size(data)::little-32, byte_size(name)::little-16, 0::little-16, name::binary>>

    central =
      <<0x02014B50::little-32, 20::little-16, 20::little-16, flags::little-16, 8::little-16,
        time::little-16, date::little-16, crc::little-32, byte_size(compressed)::little-32,
        byte_size(data)::little-32, byte_size(name)::little-16, 0::little-16, 0::little-16,
        0::little-16, 0::little-16, 0::little-32, 0::little-32, name::binary>>

    cd_offset = byte_size(local) + byte_size(compressed)

    if cd_offset + byte_size(central) < 0xFFFFFFFF do
      eocd =
        <<0x06054B50::little-32, 0::little-16, 0::little-16, 1::little-16, 1::little-16,
          byte_size(central)::little-32, cd_offset::little-32, 0::little-16>>

      {:ok, IO.iodata_to_binary([local, compressed, central, eocd])}
    else
      {:error, :zip64_unsupported}
    end
  end

  def compress(_data, :zip, _opts), do: {:error, :zip64_unsupported}

  defp deflate_raw(data) do
    z = :zlib.open()

    try do
      :ok = :zlib.deflateInit(z, :default, :deflated, -15, 8, :default)
      out = :zlib.deflate(z, data, :finish)
      :ok = :zlib.deflateEnd(z)
      IO.iodata_to_binary(out)
    after
      :zlib.close(z)
    end
  end

  ## Decompression

  # Returns {:ok, data, format}. Content that is neither GZIP nor ZIP comes
  # back as is, with format :none.
  @spec decompress(binary(), pos_integer()) ::
          {:ok, binary(), format() | :none} | {:error, term()}
  def decompress(data, max_output) do
    case detect(data) do
      :gzip -> with {:ok, out} <- gunzip(data, max_output), do: {:ok, out, :gzip}
      :zip -> with {:ok, out} <- unzip(data, max_output), do: {:ok, out, :zip}
      :none -> {:ok, data, :none}
    end
  end

  ## GZIP

  # Reads every member. After the last one only 0x00 bytes may follow.
  defp gunzip(data, max_output, acc \\ []) do
    with {:ok, member, rest} <- gunzip_member(data, max_output) do
      acc = [member | acc]
      remaining = max_output - byte_size(member)

      cond do
        zeros?(rest) -> {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
        detect(rest) == :gzip -> gunzip(rest, remaining, acc)
        true -> {:error, :gzip_trailing_data}
      end
    end
  end

  defp gunzip_member(data, max_output) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, 31)

      with {:ok, out} <- inflate(z, data, max_output),
           {:ok, rest} <- after_gzip_member(data, out) do
        {:ok, out, rest}
      end
    rescue
      e -> {:error, {:gzip, exception_reason(e)}}
    catch
      kind, reason -> {:error, {:gzip, {kind, reason}}}
    after
      :zlib.close(z)
    end
  end

  # The zlib API does not say where the member ended. The member ends with
  # its CRC-32 and ISIZE (RFC 1952 §2.3.1), which zlib has just verified, so
  # look for them.
  defp after_gzip_member(data, out) do
    trailer = <<:erlang.crc32(out)::little-32, rem(byte_size(out), 1 <<< 32)::little-32>>

    with true <- byte_size(data) >= 18,
         {pos, 8} <- :binary.match(data, trailer, scope: {10, byte_size(data) - 10}) do
      {:ok, binary_part(data, pos + 8, byte_size(data) - pos - 8)}
    else
      _ -> {:error, :gzip_bad_trailer}
    end
  end

  ## ZIP

  defp unzip(data, max_output) do
    with {:ok, eocd} <- find_eocd(data),
         <<_sig::32, disk::little-16, cd_disk::little-16, _n_disk::little-16, entries::little-16,
           _cd_size::little-32, cd_offset::little-32, _::binary>> <- eocd,
         :ok <- check(disk == 0 and cd_disk == 0, :zip_multi_disk),
         :ok <- check(entries != 0xFFFF and cd_offset != 0xFFFFFFFF, :zip64_unsupported),
         :ok <- check(entries == 1, {:zip_entry_count, entries}),
         {:ok, entry} <- central_entry(data, cd_offset),
         :ok <- check(band(entry.flags, 1) == 0, :zip_encrypted),
         :ok <- check(entry.method in [0, 8], {:zip_method, entry.method}),
         :ok <- check(entry.size <= max_output, :output_too_large),
         {:ok, compressed} <- local_data(data, entry),
         {:ok, out} <- unzip_entry(entry.method, compressed, max_output),
         :ok <- check(byte_size(out) == entry.size, :zip_size_mismatch),
         :ok <- check(:erlang.crc32(out) == entry.crc, :zip_crc_mismatch) do
      {:ok, out}
    else
      {:error, _} = error -> error
      _ -> {:error, :zip_malformed}
    end
  end

  # The End of Central Directory record is 22 bytes plus a comment of up to
  # 65535 bytes. Only 0x00 bytes may follow it (v2 padding).
  defp find_eocd(data) do
    size = byte_size(data)
    start = max(0, size - 22 - 0xFFFF - 7)

    data
    |> :binary.matches(<<"PK", 5, 6>>, scope: {start, size - start})
    |> Enum.reverse()
    |> Enum.find_value({:error, :zip_no_eocd}, fn {pos, _} -> eocd_at(data, pos) end)
  end

  defp eocd_at(data, pos) do
    with <<_::binary-20, comment_size::little-16, rest::binary>> <- from(data, pos),
         true <- byte_size(rest) >= comment_size,
         true <- zeros?(from(rest, comment_size)) do
      {:ok, binary_part(data, pos, 22)}
    else
      _ -> nil
    end
  end

  # The bytes of `data` from `offset` on (empty when it is past the end).
  defp from(data, offset) when offset <= byte_size(data),
    do: binary_part(data, offset, byte_size(data) - offset)

  defp from(_data, _offset), do: <<>>

  defp central_entry(data, offset) do
    case from(data, offset) do
      <<0x02014B50::little-32, _made::little-16, _needed::little-16, flags::little-16,
        method::little-16, _time::little-16, _date::little-16, crc::little-32, csize::little-32,
        size::little-32, _name_size::little-16, _extra::little-16, _comment::little-16,
        _disk::little-16, _int::little-16, _ext::little-32, local::little-32, _::binary>> ->
        if csize == 0xFFFFFFFF or size == 0xFFFFFFFF or local == 0xFFFFFFFF do
          {:error, :zip64_unsupported}
        else
          {:ok, %{flags: flags, method: method, crc: crc, csize: csize, size: size, local: local}}
        end

      _ ->
        {:error, :zip_malformed}
    end
  end

  defp local_data(data, %{local: offset, csize: csize}) do
    with <<0x04034B50::little-32, _::binary-22, name_size::little-16, extra_size::little-16,
           rest::binary>> <- from(data, offset),
         true <- byte_size(rest) >= name_size + extra_size + csize do
      {:ok, binary_part(rest, name_size + extra_size, csize)}
    else
      _ -> {:error, :zip_malformed}
    end
  end

  defp unzip_entry(0, stored, _max_output), do: {:ok, stored}

  defp unzip_entry(8, compressed, max_output) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, -15)
      inflate(z, compressed, max_output)
    rescue
      e -> {:error, {:zip, exception_reason(e)}}
    catch
      kind, reason -> {:error, {:zip, {kind, reason}}}
    after
      :zlib.close(z)
    end
  end

  ## Helpers

  # Inflates in bounded steps, stopping as soon as the output goes over
  # max_output. safeInflate/2 says :finished when the *input* is used up, even
  # if the stream is truncated; inflateEnd/1 raises data_error in that case.
  defp inflate(z, input, max_output, acc \\ [], size \\ 0) do
    case :zlib.safeInflate(z, input) do
      {:finished, out} ->
        inflate_finished(z, [out | acc], size + IO.iodata_length(out), max_output)

      {:continue, out} ->
        inflate_continue(z, input, out, acc, size, max_output)

      {:need_dictionary, _, _} ->
        {:error, :need_dictionary}
    end
  end

  defp inflate_finished(_z, _acc, size, max_output) when size > max_output,
    do: {:error, :output_too_large}

  defp inflate_finished(z, acc, _size, _max_output) do
    if stream_end?(z),
      do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()},
      else: {:error, :truncated}
  end

  defp inflate_continue(z, input, out, acc, size, max_output) do
    out_size = IO.iodata_length(out)

    cond do
      size + out_size > max_output -> {:error, :output_too_large}
      out_size == 0 and input == [] -> {:error, :truncated}
      true -> inflate(z, [], max_output, [out | acc], size + out_size)
    end
  end

  defp stream_end?(z) do
    :zlib.inflateEnd(z) == :ok
  rescue
    _ -> false
  end

  defp exception_reason(%ErlangError{original: original}), do: original
  defp exception_reason(%{__struct__: struct}), do: struct

  defp zeros?(bin), do: bin == :binary.copy(<<0>>, byte_size(bin))

  defp check(true, _reason), do: :ok
  defp check(false, reason), do: {:error, reason}
end
