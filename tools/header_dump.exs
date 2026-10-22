# Prints the security header of RSFN envelopes, without decrypting anything.
#
#     elixir tools/header_dump.exs [--offset N] FILE...
#
# It needs no keys and does not depend on the library, so it can run on any
# machine with Elixir. Use it to check, on real traffic, the items that the
# specification marks as market practice: the byte order of C01, which C04
# values come encrypted, how C14 and C06/C07 are filled when there is no
# encryption, and which compression format a counterpart uses.
#
# --offset N skips N bytes before the header (an audit record, for example,
# has 64 bytes before it).

defmodule HeaderDump do
  @header_size 588
  @not_encrypted [2, 3, 6, 10]

  @c04 %{
    0 => "signed and encrypted",
    1 => "certificate not yet activated",
    2 => "not encrypted, public broadcast",
    3 => "not encrypted, security related",
    4 => "file, not compressed",
    6 => "file, not compressed, not encrypted, public",
    8 => "file, compressed",
    10 => "file, compressed, not encrypted, public"
  }

  @c03 %{0xFF => "error outside the security scope"}

  @pc %{
    1 => "SPB-Serpro",
    2 => "SPB-Certisign",
    3 => "Pessoas Fisicas",
    4 => "SPB-Serasa",
    5 => "SPB-CAIXA",
    6 => "SPB-Valid",
    7 => "SPB-Soluti"
  }

  def main(argv) do
    case OptionParser.parse(argv, strict: [offset: :integer, help: :boolean]) do
      {opts, [_ | _] = files, []} ->
        if opts[:help], do: usage(0)
        offset = Keyword.get(opts, :offset, 0)
        if offset < 0, do: usage(1)
        results = Enum.map(files, &dump(&1, offset))
        if Enum.all?(results, &(&1 == :ok)), do: :ok, else: System.halt(1)

      _ ->
        usage(1)
    end
  end

  defp usage(status) do
    IO.puts(:stderr, "usage: elixir tools/header_dump.exs [--offset N] FILE...")
    System.halt(status)
  end

  defp dump(file, offset) do
    IO.puts("== #{file}")

    case File.read(file) do
      {:ok, data} when byte_size(data) >= offset + @header_size ->
        print(binary_part(data, offset, byte_size(data) - offset))

      {:ok, data} ->
        IO.puts("too short: #{byte_size(data)} bytes, need #{offset + @header_size}\n")
        :error

      {:error, reason} ->
        IO.puts("cannot read: #{:file.format_error(reason)}\n")
        :error
    end
  end

  defp print(envelope) do
    <<c01::binary-size(2), c02, c03, c04, c05, c06, c07, c08, c09, c10, c11::binary-size(32), c12,
      c13::binary-size(32), c14::binary-size(256), c15::binary-size(256), body::binary>> =
      envelope

    field("C01", "#{hex(c01)}  #{c01_note(c01)}")
    field("C02", byte(c02, version(c02)))
    field("C03", byte(c03, c03_note(c03)))
    field("C04", byte(c04, Map.get(@c04, c04, "unknown")))
    field("C05", byte(c05, if(c05 == 0, do: "", else: "(reserved, expected 0)")))
    field("C06", byte(c06, algorithm(:asym, c06)))
    field("C07", byte(c07, algorithm(:sym, c07)))
    field("C08", byte(c08, algorithm(:asym, c08)))
    field("C09", byte(c09, algorithm(:hash, c09)))
    field("C10", byte(c10, pc(c10)))
    field("C11", serial(c11))
    field("C12", byte(c12, pc(c12)))
    field("C13", serial(c13))
    field("C14", block(c14))
    field("C15", block(c15))

    empty = <<c01::binary, 0::(@header_size-2)*8>> == binary_part(envelope, 0, @header_size)
    if empty, do: IO.puts("\nall fields after C01 are zero (\"empty\" header)")

    IO.puts("")
    print_body(body, c02, c04)
    IO.puts("")
    :ok
  end

  defp print_body(body, c02, c04) do
    size = byte_size(body)
    field("body", "#{size} bytes (#{rem(size, 8)} mod 8), #{trailing_zeros(body)} trailing 0x00")
    field("first", preview(body))
    field("looks", looks_like(body))

    cond do
      c02 in [2, 3] and c04 not in @not_encrypted and is_map_key(@c04, c04) ->
        IO.puts("note: C04 says encrypted, so the format of the content is not visible")

      c02 == 2 and c04 in [2, 3, 6] and rem(size, 8) != 0 ->
        IO.puts("note: v2 without encryption and a body that is not a multiple of 8")

      true ->
        :ok
    end

    details(body)
  end

  defp field(name, value), do: IO.puts(String.pad_trailing(name, 6) <> value)

  defp byte(value, ""), do: hex(<<value>>) <> " (#{value})"
  defp byte(value, note), do: hex(<<value>>) <> " (#{value})  " <> note

  defp hex(bin),
    do:
      bin
      |> Base.encode16()
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(" ", &Enum.join/1)

  defp c01_note(<<0x02, 0x4C>>), do: "588, big-endian"
  defp c01_note(<<0x4C, 0x02>>), do: "588 only if little-endian"
  defp c01_note(<<n::16>>), do: "#{n} (expected 588)"

  defp version(2), do: "Security Protocol v2"
  defp version(3), do: "Security Protocol v3"
  defp version(0), do: ""
  defp version(_), do: "unknown version"

  defp c03_note(0), do: "no error"

  defp c03_note(code) when code in 0x01..0x14,
    do: "EGEN99" <> String.pad_leading("#{code}", 2, "0")

  defp c03_note(code), do: Map.get(@c03, code, "unknown error code")

  defp algorithm(_, 0), do: ""
  defp algorithm(:asym, 1), do: "RSA-1024"
  defp algorithm(:asym, 2), do: "RSA-2048"
  defp algorithm(:sym, 1), do: "3DES"
  defp algorithm(:sym, 2), do: "AES-256-GCM"
  defp algorithm(:hash, 2), do: "SHA-1"
  defp algorithm(:hash, 3), do: "SHA-256"
  defp algorithm(_, _), do: "unknown"

  defp pc(0), do: ""
  defp pc(code), do: Map.get(@pc, code, "PC not in the manual's table")

  defp serial(<<0::256>>), do: "all 0x00"

  defp serial(bin) do
    if bin =~ ~r/\A[0-9A-F]{32}\z/,
      do: bin,
      else:
        "#{if String.printable?(bin), do: inspect(bin), else: hex(bin)}  (not 32 uppercase hex digits)"
  end

  defp block(<<0::2048>>), do: "all 0x00"

  # RSA-1024 uses only the first 128 bytes.
  defp block(<<first::binary-size(128), 0::1024>>),
    do: "#{hex(binary_part(first, 0, 8))} ... (last 128 bytes zero)"

  defp block(bin), do: "#{hex(binary_part(bin, 0, 8))} ... (not zero)"

  defp trailing_zeros(bin), do: byte_size(bin) - without_zeros(bin, byte_size(bin))

  defp without_zeros(_bin, 0), do: 0

  defp without_zeros(bin, n) do
    if :binary.at(bin, n - 1) == 0, do: without_zeros(bin, n - 1), else: n
  end

  defp preview(""), do: "(empty)"

  defp preview(body) do
    head = binary_part(body, 0, min(16, byte_size(body)))
    ascii = for <<c <- head>>, into: "", do: if(c in 0x20..0x7E, do: <<c>>, else: ".")
    "#{hex(head)}  |#{ascii}|"
  end

  defp looks_like(<<0x1F, 0x8B, _::binary>>), do: "GZIP"
  defp looks_like(<<"PK", 3, 4, _::binary>>), do: "ZIP"
  defp looks_like(<<"PK", 5, 6, _::binary>>), do: "ZIP (empty)"
  defp looks_like(<<"PK", 7, 8, _::binary>>), do: "ZIP (spanned)"
  defp looks_like(""), do: "nothing"

  defp looks_like(body) do
    sample = binary_part(body, 0, min(512, byte_size(body)))

    text =
      for <<c <- sample>>, c in 0x20..0x7E or c in [9, 10, 13] or c >= 0x80,
        reduce: 0,
        do: (n -> n + 1)

    cond do
      String.valid?(sample) and text * 10 >= byte_size(sample) * 9 -> "text"
      utf16?(sample) -> "text (UTF-16)"
      true -> "binary (encrypted or unknown)"
    end
  end

  defp utf16?(<<0xFE, 0xFF, _::binary>>), do: true
  defp utf16?(<<0xFF, 0xFE, _::binary>>), do: true
  defp utf16?(<<0, c, _::binary>>) when c in 0x20..0x7E, do: true
  defp utf16?(_), do: false

  # GZIP: RFC 1952 member header.
  defp details(<<0x1F, 0x8B, method, flags, mtime::little-32, _xfl, os, rest::binary>>) do
    name = if Bitwise.band(flags, 0x08) != 0, do: gzip_name(flags, rest), else: "(none)"

    field(
      "gzip",
      "method #{method}, flags 0x#{hex(<<flags>>)}, mtime #{mtime}, os #{os}, name #{name}"
    )
  end

  # ZIP: first local file header (APPNOTE 4.3.7).
  defp details(
         <<"PK", 3, 4, version::little-16, flags::little-16, method::little-16, _time::little-32,
           _crc::little-32, csize::little-32, usize::little-32, name_len::little-16,
           _extra_len::little-16, name::binary-size(name_len), _::binary>>
       ) do
    field(
      "zip",
      "first entry #{inspect(name)}, method #{method}, flags 0x#{Base.encode16(<<flags::16>>)}, " <>
        "version #{version}, sizes #{csize}/#{usize}"
    )
  end

  defp details(_body), do: :ok

  defp gzip_name(flags, rest) do
    rest =
      case {Bitwise.band(flags, 0x04), rest} do
        {0, rest} -> rest
        {_, <<xlen::little-16, _::binary-size(xlen), rest::binary>>} -> rest
        _ -> ""
      end

    case :binary.split(rest, <<0>>) do
      [name, _] -> inspect(name)
      _ -> "(truncated)"
    end
  end
end

HeaderDump.main(System.argv())
