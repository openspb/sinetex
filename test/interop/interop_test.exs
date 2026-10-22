defmodule Sinetex.InteropTest do
  # Seals with one implementation and opens with the other, in both
  # directions: the library and test/interop/oracle.py, an independent
  # implementation written from docs/SPEC.md.
  use ExUnit.Case, async: true

  import Sinetex.Fixtures
  alias Sinetex.{Error, Header}

  @moduletag :interop
  @moduletag :tmp_dir

  @oracle Path.expand("oracle.py", __DIR__)

  @combos for version <- [2, 3],
              {c04, compression} <- [
                {0, nil},
                {1, nil},
                {2, nil},
                {3, nil},
                {4, nil},
                {6, nil},
                {8, :gzip},
                {8, :zip},
                {10, :gzip},
                {10, :zip}
              ],
              do: {version, c04, compression}

  setup_all do
    %{a: identity("bank_a"), b: identity("bank_b")}
  end

  defp oracle(args) do
    python = Application.fetch_env!(:sinetex, :test_python)
    System.cmd(python, [@oracle | args], stderr_to_stdout: true)
  end

  defp contents do
    [
      "",
      "x",
      "<DOC>interop</DOC>",
      :crypto.strong_rand_bytes(100_003),
      String.duplicate("<ROW/>", 20_000)
    ]
  end

  defp expected(content, 2, nil),
    do: content <> :binary.copy(<<0>>, rem(8 - rem(byte_size(content), 8), 8))

  defp expected(content, _version, _compression), do: content

  test "library seals, oracle opens", %{tmp_dir: dir} = ctx do
    for {version, c04, compression} <- @combos, {content, i} <- Enum.with_index(contents()) do
      opts = [from: ctx.a, to: ctx.b.certificate, version: version, c04: c04]
      opts = if compression, do: [compression: compression] ++ opts, else: opts
      {:ok, envelope} = Sinetex.seal(content, opts)

      input = Path.join(dir, "env-#{version}-#{c04}-#{compression}-#{i}")
      output = input <> ".out"
      File.write!(input, envelope)

      {json, status} =
        oracle([
          "open",
          "--cert",
          path("bank_b.crt"),
          "--key",
          path("bank_b.key"),
          "--from",
          path("bank_a.crt"),
          input,
          output
        ])

      label = inspect({version, c04, compression, byte_size(content)})
      assert status == 0, "#{label}: #{json}"
      assert File.read!(output) == expected(content, version, compression), label
      assert json == "ok c03=0 c04=#{c04} compression=#{compression || :none}\n"
    end
  end

  test "oracle seals, library opens", %{tmp_dir: dir} = ctx do
    for {version, c04, compression} <- @combos, {content, i} <- Enum.with_index(contents()) do
      input = Path.join(dir, "content-#{i}")
      output = Path.join(dir, "env-#{version}-#{c04}-#{compression}-#{i}")
      File.write!(input, content)

      args =
        [
          "seal",
          "--cert",
          path("bank_a.crt"),
          "--key",
          path("bank_a.key"),
          "--to",
          path("bank_b.crt"),
          "--version",
          "#{version}",
          "--c04",
          "#{c04}"
        ] ++
          if(compression, do: ["--compression", "#{compression}"], else: []) ++ [input, output]

      {out, 0} = oracle(args)
      assert out == ""

      label = inspect({version, c04, compression, byte_size(content)})

      assert {:ok, opened} = Sinetex.open(File.read!(output), as: ctx.b, from: ctx.a.certificate),
             label

      assert opened.content == expected(content, version, compression), label
      assert opened.compression == (compression || :none)
    end
  end

  test "both report the same error codes", %{tmp_dir: dir} = ctx do
    {:ok, envelope} = Sinetex.seal("<DOC/>", from: ctx.a, to: ctx.b.certificate)
    {:ok, v2} = Sinetex.seal("<DOC/>", from: ctx.a, to: ctx.b.certificate, version: 2)
    other = certificate("bank_c")

    cases = [
      tamper_header(envelope, &%{&1 | c09: 2}),
      tamper_header(envelope, &%{&1 | c11: other.serial_field}),
      tamper_header(envelope, &%{&1 | c13: other.serial_field}),
      tamper_header(envelope, &%{&1 | c14: flip_byte(&1.c14, 3)}),
      tamper_header(envelope, &%{&1 | c15: flip_byte(&1.c15, 3)}),
      tamper_header(envelope, &%{&1 | c04: 5}),
      flip_byte(envelope, byte_size(envelope) - 1),
      v2 <> "x",
      binary_part(envelope, 0, 100)
    ]

    for {tampered, i} <- Enum.with_index(cases) do
      input = Path.join(dir, "bad-#{i}")
      File.write!(input, tampered)

      {json, 1} =
        oracle([
          "open",
          "--cert",
          path("bank_b.crt"),
          "--key",
          path("bank_b.key"),
          "--from",
          path("bank_a.crt"),
          input,
          input <> ".out"
        ])

      ["error", code] = String.split(json)
      oracle_code = String.to_integer(code)

      assert {:error, %Error{c03: ^oracle_code}} =
               Sinetex.open(tampered, as: ctx.b, from: ctx.a.certificate),
             "case #{i}: #{inspect(Header.decode(tampered) |> elem(0))}"
    end
  end
end
