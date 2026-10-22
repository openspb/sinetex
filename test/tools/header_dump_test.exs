defmodule Sinetex.HeaderDumpTest do
  use ExUnit.Case, async: true

  import Sinetex.Fixtures

  @moduletag :tmp_dir
  @script Path.expand("../../tools/header_dump.exs", __DIR__)

  defp dump(args) do
    System.cmd(System.find_executable("elixir"), [@script | args], stderr_to_stdout: true)
  end

  test "prints the header of an encrypted envelope", %{tmp_dir: dir} do
    {:ok, envelope} = Sinetex.seal("content", from: identity("bank_a"), to: certificate("bank_b"))
    file = Path.join(dir, "envelope")
    File.write!(file, envelope)

    {output, 0} = dump([file])
    assert output =~ "C01   02 4C  588, big-endian"
    assert output =~ "C04   00 (0)  signed and encrypted"
    assert output =~ "C11   0000000000000000000000003B3BC056"
    assert output =~ "C13   5D77DA7B6F02EFA1EDDA741E78FF3508"
    assert output =~ ~r/C14   .* \(not zero\)/
    assert output =~ "note: C04 says encrypted"
  end

  test "shows the compression format when the body is not encrypted", %{tmp_dir: dir} do
    me = identity("bank_a")

    for {format, expected} <- [gzip: "looks GZIP", zip: ~s(first entry "content")] do
      {:ok, envelope} = Sinetex.seal("content", from: me, c04: 10, compression: format)
      file = Path.join(dir, "#{format}")
      File.write!(file, envelope)

      {output, 0} = dump([file])
      assert output =~ "C14   all 0x00"
      assert output =~ expected
    end
  end

  test "--offset and errors", %{tmp_dir: dir} do
    {:ok, envelope} = Sinetex.seal("x", from: identity("bank_a"), c04: 3)
    file = Path.join(dir, "record")
    File.write!(file, :binary.copy(<<0xAB>>, 64) <> envelope)

    assert {output, 0} = dump(["--offset", "64", file])
    assert output =~ "C02   03 (3)"

    assert {output, 1} = dump([file, Path.join(dir, "missing")])
    assert output =~ "cannot read"

    assert {_, 1} = dump([])
  end
end
