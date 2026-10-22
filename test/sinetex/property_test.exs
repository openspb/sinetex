defmodule Sinetex.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Sinetex.Fixtures
  alias Sinetex.{Error, Header}

  @c04_values [0, 1, 2, 3, 4, 6, 8, 10]
  @not_encrypted [2, 3, 6, 10]

  setup_all do
    %{a: identity("bank_a"), b: identity("bank_b"), cert_a: certificate("bank_a")}
  end

  defp options do
    gen all version <- member_of([2, 3]),
            c04 <- member_of(@c04_values),
            compression <- member_of([:gzip, :zip]) do
      [version: version, c04: c04] ++ if(c04 in [8, 10], do: [compression: compression], else: [])
    end
  end

  defp open(ctx, envelope, opts \\ []) do
    Sinetex.open(envelope, [as: ctx.b, from: ctx.cert_a] ++ opts)
  end

  property "open(seal(content)) == content", ctx do
    check all content <- binary(max_length: 2048), opts <- options(), max_runs: 200 do
      {:ok, envelope} = Sinetex.seal(content, [from: ctx.a, to: ctx.b.certificate] ++ opts)
      assert {:ok, opened} = open(ctx, envelope, trim_padding: false)

      if opts[:version] == 2 and opts[:c04] not in [8, 10] do
        padding = rem(8 - rem(byte_size(content), 8), 8)
        assert opened.content == content <> :binary.copy(<<0>>, padding)
      else
        assert opened.content == content
      end
    end
  end

  # The header is not signed (the protocol signs only the content), so C03,
  # C04 and C05 can change without an error, and so can the recipient
  # fields when there is no encryption. Every other byte is covered.
  defp covered?(pos, c04) do
    cond do
      pos in [3, 4, 5] -> false
      c04 in @not_encrypted and (pos == 6 or pos in 10..42 or pos in 76..331) -> false
      true -> true
    end
  end

  property "changing any covered byte gives an error", ctx do
    check all content <- binary(min_length: 1, max_length: 512),
              opts <- options(),
              {:ok, envelope} =
                Sinetex.seal(content, [from: ctx.a, to: ctx.b.certificate] ++ opts),
              pos <- integer(0..(byte_size(envelope) - 1)),
              covered?(pos, opts[:c04]),
              mask <- integer(1..255),
              max_runs: 500 do
      rest = binary_part(envelope, pos + 1, byte_size(envelope) - pos - 1)
      byte = Bitwise.bxor(:binary.at(envelope, pos), mask)
      tampered = binary_part(envelope, 0, pos) <> <<byte>> <> rest
      assert {:error, %Error{}} = open(ctx, tampered)
    end
  end

  property "malformed input never raises", ctx do
    random_header =
      gen all bytes <- list_of(integer(0..255), length: 12),
              c11 <- member_of([ctx.b.certificate.serial_field, <<0::256>>, "ZZ"]),
              c13 <- member_of([ctx.cert_a.serial_field, <<0::256>>, "ZZ"]),
              c14 <- binary(length: 256),
              c15 <- binary(length: 256) do
        [c02, c03, c04, c05, c06, c07, c08, c09, c10, c12, c01_hi, c01_lo] = bytes
        c01 = if c01_hi < 200, do: 588, else: c01_hi * 256 + c01_lo
        pad = fn s -> binary_part(s <> <<0::256>>, 0, 32) end

        <<c01::16, c02, c03, c04, c05, c06, c07, c08, c09, c10, pad.(c11)::binary, c12,
          pad.(c13)::binary, c14::binary, c15::binary>>
      end

    check all input <- one_of([binary(max_length: 1200), random_header]),
              body <- binary(max_length: 64),
              uniform <- boolean(),
              max_runs: 2000 do
      result =
        open(ctx, input <> body,
          c14_errors: if(uniform, do: :uniform, else: :manual),
          allow_clear: true
        )

      assert match?({:ok, %Sinetex.Opened{}}, result) or match?({:error, %Error{}}, result)
    end
  end

  property "valid headers with a random body never raise", ctx do
    check all opts <- options(), body <- binary(max_length: 300), max_runs: 300 do
      {:ok, envelope} = Sinetex.seal("x", [from: ctx.a, to: ctx.b.certificate] ++ opts)
      {:ok, header, _} = Header.decode(envelope)
      result = open(ctx, Header.encode(header) <> body)
      assert match?({:ok, _}, result) or match?({:error, %Error{}}, result)
    end
  end
end
