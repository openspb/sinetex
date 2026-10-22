defmodule Sinetex.CompressionTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sinetex.Compression

  @max 10_000_000

  setup_all do
    %{data: :crypto.strong_rand_bytes(70_000) <> String.duplicate("RSFN ", 50_000)}
  end

  defp zeros(n), do: :binary.copy(<<0>>, n)

  describe "GZIP" do
    test "roundtrip", %{data: data} do
      {:ok, gz} = Compression.compress(data, :gzip, [])
      assert Compression.detect(gz) == :gzip
      assert Compression.decompress(gz, @max) == {:ok, data, :gzip}
    end

    test "tolerates the v2 padding after the member", %{data: data} do
      {:ok, gz} = Compression.compress(data, :gzip, [])

      for n <- 1..7,
          do: assert(Compression.decompress(gz <> zeros(n), @max) == {:ok, data, :gzip})
    end

    test "reads every member" do
      {:ok, a} = Compression.compress("hello ", :gzip, [])
      {:ok, b} = Compression.compress("world", :gzip, [])
      assert Compression.decompress(a <> b <> zeros(3), @max) == {:ok, "hello world", :gzip}
    end

    test "content whose size ends in zero bytes" do
      # ISIZE = 256 = <<0, 1, 0, 0>>: its trailing zeros look like padding.
      data = :crypto.strong_rand_bytes(256)
      {:ok, gz} = Compression.compress(data, :gzip, [])
      assert Compression.decompress(gz <> zeros(5), @max) == {:ok, data, :gzip}
    end

    test "rejects data after the member", %{data: data} do
      {:ok, gz} = Compression.compress(data, :gzip, [])
      assert Compression.decompress(gz <> "junk", @max) == {:error, :gzip_trailing_data}
    end

    test "rejects truncated and corrupted streams", %{data: data} do
      {:ok, gz} = Compression.compress(data, :gzip, [])
      assert {:error, _} = Compression.decompress(binary_part(gz, 0, div(byte_size(gz), 2)), @max)
      assert {:error, _} = Compression.decompress(binary_part(gz, 0, 12), @max)
      assert {:error, _} = Compression.decompress(<<0x1F, 0x8B>>, @max)
      corrupted = Sinetex.Fixtures.flip_byte(gz, byte_size(gz) - 6)
      assert {:error, _} = Compression.decompress(corrupted, @max)
    end

    test "caps the output" do
      bomb = :zlib.gzip(zeros(20_000_000))
      assert byte_size(bomb) < 30_000
      assert Compression.decompress(bomb, 1_000_000) == {:error, :output_too_large}
      assert {:ok, _, :gzip} = Compression.decompress(bomb, 20_000_000)
      assert Compression.decompress(bomb, 19_999_999) == {:error, :output_too_large}
    end

    test "the cap covers every member" do
      {:ok, a} = Compression.compress(zeros(600), :gzip, [])
      assert {:ok, _, :gzip} = Compression.decompress(a <> a, 1200)
      assert Compression.decompress(a <> a, 1199) == {:error, :output_too_large}
    end
  end

  describe "compression level" do
    test "the default output is the one of :zlib.gzip/1", %{data: data} do
      assert Compression.compress(data, :gzip, []) == {:ok, :zlib.gzip(data)}

      assert Compression.compress(data, :gzip, compression_level: :default) ==
               {:ok, :zlib.gzip(data)}

      assert Compression.compress(data, :zip, zip_entry_name: "c") ==
               Compression.compress(data, :zip, zip_entry_name: "c", compression_level: :default)
    end

    test "every level reads back", %{data: data} do
      for format <- [:gzip, :zip], level <- [:none, :best_speed, :best_compression, 0, 1, 9] do
        opts = [zip_entry_name: "c", compression_level: level]
        {:ok, packed} = Compression.compress(data, format, opts)
        assert Compression.decompress(packed, @max) == {:ok, data, format}, inspect(level)
      end

      {:ok, stored} = Compression.compress(data, :gzip, compression_level: :none)
      {:ok, best} = Compression.compress(data, :gzip, compression_level: :best_compression)
      assert byte_size(stored) > byte_size(data)
      assert byte_size(best) < byte_size(data)
    end
  end

  describe "ZIP" do
    test "roundtrip, readable by OTP's :zip", %{data: data} do
      {:ok, zip} = Compression.compress(data, :zip, zip_entry_name: "arquivo.xml")
      assert Compression.detect(zip) == :zip
      assert Compression.decompress(zip, @max) == {:ok, data, :zip}
      assert {:ok, [{~c"arquivo.xml", ^data}]} = :zip.unzip(zip, [:memory])
    end

    test "output is deterministic", %{data: data} do
      opts = [zip_entry_name: "content"]
      assert Compression.compress(data, :zip, opts) == Compression.compress(data, :zip, opts)
    end

    test "reads archives written by OTP's :zip (stored and deflated)", %{data: data} do
      {:ok, {_, deflated}} = :zip.zip(~c"x.zip", [{~c"a.txt", data}], [:memory])
      assert Compression.decompress(deflated, @max) == {:ok, data, :zip}

      {:ok, {_, stored}} =
        :zip.zip(~c"x.zip", [{~c"a.txt", "tiny"}], [:memory, {:uncompress, :all}])

      assert Compression.decompress(stored, @max) == {:ok, "tiny", :zip}
    end

    test "tolerates the v2 padding after the End of Central Directory", %{data: data} do
      {:ok, zip} = Compression.compress(data, :zip, zip_entry_name: "content")

      for n <- 1..7,
          do: assert(Compression.decompress(zip <> zeros(n), @max) == {:ok, data, :zip})
    end

    test "rejects anything but a single entry" do
      {:ok, {_, two}} = :zip.zip(~c"x.zip", [{~c"a", "1"}, {~c"b", "2"}], [:memory])
      assert Compression.decompress(two, @max) == {:error, {:zip_entry_count, 2}}

      empty = <<"PK", 5, 6, 0::18*8>>
      assert Compression.decompress(empty, @max) == {:error, {:zip_entry_count, 0}}
    end

    test "rejects corrupted archives", %{data: data} do
      {:ok, zip} = Compression.compress(data, :zip, zip_entry_name: "content")
      assert {:error, _} = Compression.decompress(zip <> "junk", @max)
      assert {:error, _} = Compression.decompress(binary_part(zip, 0, byte_size(zip) - 30), @max)
      # Corrupt the compressed data: CRC or inflate fails.
      assert {:error, _} = Compression.decompress(Sinetex.Fixtures.flip_byte(zip, 100), @max)
    end

    test "caps the output, even when the declared size lies" do
      {:ok, bomb} = Compression.compress(zeros(20_000_000), :zip, zip_entry_name: "content")
      assert Compression.decompress(bomb, 1_000_000) == {:error, :output_too_large}

      # Rewrite the uncompressed size in the central directory to 1 byte.
      {pos, _} = :binary.match(bomb, <<"PK", 1, 2>>)
      at = pos + 24
      rest = binary_part(bomb, at + 4, byte_size(bomb) - at - 4)
      lying = binary_part(bomb, 0, at) <> <<1::little-32>> <> rest
      assert Compression.decompress(lying, 1_000_000) == {:error, :output_too_large}
    end
  end

  test "content without magic bytes comes back as is" do
    assert Compression.decompress("<xml/>", @max) == {:ok, "<xml/>", :none}
    assert Compression.decompress("", @max) == {:ok, "", :none}
  end

  property "decompress never raises" do
    prefixes =
      member_of([<<0x1F, 0x8B, 8, 0>>, <<"PK", 3, 4>>, <<"PK", 5, 6>>, <<"PK", 7, 8>>, <<>>])

    check all prefix <- prefixes, rest <- binary(max_length: 300), max_runs: 1000 do
      assert match?({:ok, _, _}, Compression.decompress(prefix <> rest, 10_000)) or
               match?({:error, _}, Compression.decompress(prefix <> rest, 10_000))
    end
  end

  property "roundtrip" do
    check all data <- binary(max_length: 5000),
              format <- member_of([:gzip, :zip]),
              pad <- integer(0..7) do
      {:ok, packed} = Compression.compress(data, format, zip_entry_name: "content")
      assert Compression.decompress(packed <> zeros(pad), 10_000) == {:ok, data, format}
    end
  end
end
