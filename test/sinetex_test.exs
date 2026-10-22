defmodule SinetexTest do
  use ExUnit.Case, async: true

  import Sinetex.Fixtures
  alias Sinetex.{Error, Header, Opened}

  doctest Sinetex

  setup_all do
    %{
      a: identity("bank_a"),
      b: identity("bank_b"),
      cert_a: certificate("bank_a"),
      cert_b: certificate("bank_b"),
      cert_c: certificate("bank_c")
    }
  end

  @content ~s(<?xml version="1.0"?><DOC><BCMSG/><SISMSG>GEN0001</SISMSG></DOC>)

  defp seal!(ctx, content \\ @content, opts \\ []) do
    {:ok, envelope} = Sinetex.seal(content, Keyword.merge([from: ctx.a, to: ctx.cert_b], opts))
    envelope
  end

  defp open(ctx, envelope, opts \\ []) do
    Sinetex.open(envelope, Keyword.merge([as: ctx.b, from: ctx.cert_a], opts))
  end

  defp c03(result) do
    assert {:error, %Error{c03: c03}} = result
    c03
  end

  defp pad8(content) do
    content <> :binary.copy(<<0>>, rem(8 - rem(byte_size(content), 8), 8))
  end

  describe "roundtrip" do
    test "v3 is the default", ctx do
      envelope = seal!(ctx)
      assert {:ok, %Header{c02: 3, c07: 2}, _} = Header.decode(envelope)
      # No padding in v3; the GCM tag (16 bytes) goes at the end of the body.
      assert byte_size(envelope) == 588 + byte_size(@content) + 16

      assert {:ok, %Opened{} = opened} = open(ctx, envelope)
      assert opened.content == @content
      assert opened.protection == :signed_and_encrypted
      assert opened.compression == :none
      assert opened.sender == ctx.cert_a
      assert opened.header.c03 == 0
    end

    test "every version, C04 and compression", ctx do
      combos =
        for version <- [2, 3],
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

      for {version, c04, compression} <- combos,
          content <- ["", "x", @content, :crypto.strong_rand_bytes(1000)] do
        opts =
          [version: version, c04: c04] ++
            if(compression, do: [compression: compression], else: [])

        envelope = seal!(ctx, content, opts)
        label = inspect({version, c04, compression, byte_size(content)})

        assert {:ok, opened} = open(ctx, envelope), label

        expected = if version == 2 and compression == nil, do: pad8(content), else: content
        assert opened.content == expected, label
        assert opened.header.c04 == c04
        assert opened.compression == (compression || :none)

        assert opened.protection ==
                 if(c04 in [2, 3, 6, 10], do: :signed, else: :signed_and_encrypted)
      end
    end

    test "header fields (§5.2)", ctx do
      {:ok, header, _body} = Header.decode(seal!(ctx, @content, version: 2))

      assert %Header{
               c01: 588,
               c02: 2,
               c03: 0,
               c04: 0,
               c05: 0,
               c06: 2,
               c07: 1,
               c08: 2,
               c09: 3,
               c10: 6,
               c12: 6
             } = header

      assert header.c11 == "0000000000000000000000003B3BC056"
      assert header.c13 == "5D77DA7B6F02EFA1EDDA741E78FF3508"
    end

    test "without encryption C14 is zeroed and the body is the signed content", ctx do
      envelope = seal!(ctx, @content, c04: 2)
      {:ok, header, body} = Header.decode(envelope)
      assert header.c14 == <<0::2048>>
      assert body == @content
      # C06/C07 keep the values of the version.
      assert {header.c06, header.c07} == {2, 2}
    end

    test "public broadcast without recipient", ctx do
      {:ok, envelope} = Sinetex.seal(@content, from: ctx.a, c04: 2)
      {:ok, header, _} = Header.decode(envelope)
      assert {header.c10, header.c11} == {0, <<0::256>>}
      assert {:ok, %{content: @content, protection: :signed}} = open(ctx, envelope)
    end

    test "large content (chunked hashing)", ctx do
      content = :crypto.strong_rand_bytes(3_500_000)

      for version <- [2, 3] do
        assert {:ok, %{content: opened}} = open(ctx, seal!(ctx, content, version: version))
        assert binary_part(opened, 0, byte_size(content)) == content
      end
    end

    test "v2 padding stays unless trim_padding: true", ctx do
      envelope = seal!(ctx, "abc", version: 2)
      assert {:ok, %{content: "abc" <> <<0, 0, 0, 0, 0>>}} = open(ctx, envelope)
      assert {:ok, %{content: "abc"}} = open(ctx, envelope, trim_padding: true)

      # Legitimate trailing zeros are removed too (documented).
      assert {:ok, %{content: "abc"}} =
               open(ctx, seal!(ctx, "abc\0", version: 2), trim_padding: true)

      # No effect on v3 or on decompressed content.
      assert {:ok, %{content: "abc\0"}} = open(ctx, seal!(ctx, "abc\0"), trim_padding: true)

      gz = seal!(ctx, "abc\0", version: 2, c04: 8, compression: :gzip)
      assert {:ok, %{content: "abc\0"}} = open(ctx, gz, trim_padding: true)
    end

    test "v2 + compression: the reader skips the padding after the archive", ctx do
      for compression <- [:gzip, :zip], content <- ["a", "abcdefgh", @content] do
        envelope = seal!(ctx, content, version: 2, c04: 8, compression: compression)
        assert {:ok, %{content: ^content, compression: ^compression}} = open(ctx, envelope)
      end
    end

    test "C04 8 with content that is not compressed comes back as is", ctx do
      # Market practice: some answers marked as compressed arrive in clear.
      envelope = seal!(ctx, @content, c04: 4) |> tamper_header(&%{&1 | c04: 8})
      assert {:ok, %{content: @content, compression: :none}} = open(ctx, envelope)
    end

    test "ZIP entry name", ctx do
      envelope = seal!(ctx, @content, c04: 10, compression: :zip, zip_entry_name: "ARQ.xml")
      {:ok, _header, body} = Header.decode(envelope)
      assert {:ok, [{~c"ARQ.xml", @content}]} = :zip.unzip(body, [:memory])
    end

    test "several expected senders", ctx do
      envelope = seal!(ctx)
      assert {:ok, %{sender: sender}} = open(ctx, envelope, from: [ctx.cert_c, ctx.cert_a])
      assert sender == ctx.cert_a
    end

    test "certificate outside the SPB standard, with explicit PC", ctx do
      chamber = identity("chamber", pc: 4)
      {:ok, envelope} = Sinetex.seal(@content, from: chamber, to: ctx.cert_b)
      {:ok, header, _} = Header.decode(envelope)
      assert header.c12 == 4
      assert {:ok, _} = open(ctx, envelope, from: certificate("chamber", pc: 4))
    end

    test "serial numbers given with serial:", ctx do
      # long_serial does not fit C11/C13 unless both sides agree on a number.
      long = identity("long_serial", serial: 0xABCD)
      {:ok, envelope} = Sinetex.seal(@content, from: long, to: ctx.cert_b)
      {:ok, header, _} = Header.decode(envelope)
      assert header.c13 == "0000000000000000000000000000ABCD"

      assert {:ok, %Opened{content: @content}} =
               open(ctx, envelope, from: certificate("long_serial", serial: 0xABCD))

      # A recipient known by another number.
      {:ok, to_alias} =
        Sinetex.seal(@content, from: ctx.a, to: certificate("bank_b", serial: 0x0B))

      assert c03(open(ctx, to_alias)) == 0x08
      me = identity("bank_b", serial: 0x0B)
      assert {:ok, %Opened{content: @content}} = Sinetex.open(to_alias, as: me, from: ctx.cert_a)
    end

    test "compression level", ctx do
      for format <- [:gzip, :zip], level <- [:none, :best_speed, :best_compression, 6] do
        opts = [c04: 8, compression: format, compression_level: level]
        assert {:ok, %Opened{content: @content}} = open(ctx, seal!(ctx, @content, opts))
      end
    end
  end

  describe "seal/2 errors" do
    test "compression is required with C04 8 and 10", ctx do
      assert Sinetex.seal("x", from: ctx.a, to: ctx.cert_b, c04: 8) ==
               {:error, :compression_required}

      assert Sinetex.seal("x", from: ctx.a, c04: 10) == {:error, :compression_required}
    end

    test "recipient is required when encrypting", ctx do
      for c04 <- [0, 1, 4] do
        assert Sinetex.seal("x", from: ctx.a, c04: c04) == {:error, :recipient_required}
      end

      assert Sinetex.seal("x", from: ctx.a, c04: 8, compression: :gzip) ==
               {:error, :recipient_required}
    end

    test "invalid options raise", ctx do
      base = [from: ctx.a, to: ctx.cert_b]

      for bad <- [
            [c04: 5],
            [version: 1],
            [compression: :gzip],
            [compression: :bzip2, c04: 8],
            [from: nil],
            [to: :someone],
            [unknown: 1],
            [zip_entry_name: ""],
            [compression_level: :best_speed],
            [compression_level: :fast, c04: 8, compression: :gzip],
            [compression_level: 10, c04: 8, compression: :gzip]
          ] do
        assert_raise ArgumentError, fn -> Sinetex.seal("x", Keyword.merge(base, bad)) end
      end

      assert_raise ArgumentError, fn -> Sinetex.seal("x", to: ctx.cert_b) end
    end
  end

  describe "error table (§5.5.1): one case per code" do
    test "0x01 header size", ctx do
      envelope = seal!(ctx)
      assert c03(open(ctx, binary_part(envelope, 0, 587))) == 0x01
      assert c03(open(ctx, "")) == 0x01
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c01: 0}))) == 0x01
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c01: 0x4C02}))) == 0x01
    end

    test "0x02 version", ctx do
      envelope = seal!(ctx)

      for v <- [0, 1, 4, 0xFF],
          do: assert(c03(open(ctx, tamper_header(envelope, &%{&1 | c02: v}))) == 0x02)
    end

    test "0x03 recipient key algorithm", ctx do
      envelope = seal!(ctx)

      for v <- [0, 1, 3],
          do: assert(c03(open(ctx, tamper_header(envelope, &%{&1 | c06: v}))) == 0x03)

      # Not checked without encryption.
      plain = seal!(ctx, @content, c04: 2)
      assert {:ok, _} = open(ctx, tamper_header(plain, &%{&1 | c06: 1}))
    end

    test "0x04 symmetric algorithm, and its match with the version", ctx do
      v3 = seal!(ctx)
      v2 = seal!(ctx, @content, version: 2)
      assert c03(open(ctx, tamper_header(v3, &%{&1 | c07: 1}))) == 0x04
      assert c03(open(ctx, tamper_header(v2, &%{&1 | c07: 2}))) == 0x04
      assert c03(open(ctx, tamper_header(v3, &%{&1 | c07: 3}))) == 0x04
      # Without encryption C07 is still checked, but 0x00 is accepted (below).
      signed = seal!(ctx, @content, c04: 2)
      assert c03(open(ctx, tamper_header(signed, &%{&1 | c07: 1}))) == 0x04
      assert c03(open(ctx, tamper_header(signed, &%{&1 | c07: 3}))) == 0x04
      # With encryption 0x00 is an error.
      assert c03(open(ctx, tamper_header(v3, &%{&1 | c07: 0}))) == 0x04
      assert c03(open(ctx, tamper_header(v2, &%{&1 | c07: 0}))) == 0x04
    end

    test "without encryption C06 and C07 may be 0x00", ctx do
      for version <- [2, 3], c04 <- [2, 3, 6, 10] do
        opts = [version: version, c04: c04] ++ if(c04 == 10, do: [compression: :gzip], else: [])
        envelope = tamper_header(seal!(ctx, @content, opts), &%{&1 | c06: 0, c07: 0, c10: 0})
        assert {:ok, %Opened{protection: :signed}} = open(ctx, envelope)
      end
    end

    test "0x05 sender key algorithm", ctx do
      assert c03(open(ctx, tamper_header(seal!(ctx), &%{&1 | c08: 1}))) == 0x05
    end

    test "0x06 hash algorithm (SHA-1 is refused)", ctx do
      assert c03(open(ctx, tamper_header(seal!(ctx), &%{&1 | c09: 2}))) == 0x06
      assert c03(open(ctx, tamper_header(seal!(ctx), &%{&1 | c09: 0}))) == 0x06
    end

    test "0x07 PC of the recipient certificate", ctx do
      assert c03(open(ctx, tamper_header(seal!(ctx), &%{&1 | c10: 1}))) == 0x07
    end

    test "0x08 serial of the recipient certificate", ctx do
      envelope = seal!(ctx)

      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c11: ctx.cert_c.serial_field}))) ==
               0x08

      lower = String.downcase(ctx.cert_b.serial_field)
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c11: lower}))) == 0x08
      # Encrypted to someone else: the recipient fields say so.
      {:ok, to_c} = Sinetex.seal(@content, from: ctx.a, to: ctx.cert_c)
      assert c03(open(ctx, to_c)) == 0x08
    end

    test "0x09 PC of the sender certificate", ctx do
      envelope = seal!(ctx)
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c12: 2}))) == 0x09
      # Unknown serial and invalid PC: 0x09 is the lower code.
      tampered = tamper_header(envelope, &%{&1 | c12: 0, c13: ctx.cert_c.serial_field})
      assert c03(open(ctx, tampered)) == 0x09
    end

    test "0x0A serial of the sender certificate", ctx do
      envelope = seal!(ctx)

      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c13: ctx.cert_c.serial_field}))) ==
               0x0A

      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c13: <<0::256>>}))) == 0x0A
      assert c03(open(ctx, envelope, from: ctx.cert_c)) == 0x0A
    end

    test "0x0B signature", ctx do
      envelope = seal!(ctx)
      bad_sig = tamper_header(envelope, &%{&1 | c15: flip_byte(&1.c15, 10)})
      assert c03(open(ctx, bad_sig)) == 0x0B

      # Without encryption, any change in the body breaks the signature.
      plain = seal!(ctx, @content, c04: 3)
      assert c03(open(ctx, flip_byte(plain, 600))) == 0x0B

      # Signed by someone else, with the right header.
      {:ok, by_c} = Sinetex.seal(@content, from: identity("bank_c"), to: ctx.cert_b)
      forged = tamper_header(by_c, &%{&1 | c13: ctx.cert_a.serial_field})
      assert c03(open(ctx, forged)) == 0x0B
    end

    test "0x0C certificate known, but not of the sender", ctx do
      {:ok, by_c} = Sinetex.seal(@content, from: identity("bank_c"), to: ctx.cert_b)
      assert c03(open(ctx, by_c, known: [ctx.cert_c])) == 0x0C
      assert c03(open(ctx, by_c)) == 0x0A
    end

    test "0x0D symmetric key extraction (C14)", ctx do
      for version <- [2, 3] do
        envelope = seal!(ctx, @content, version: version)
        bad_c14 = tamper_header(envelope, &%{&1 | c14: flip_byte(&1.c14, 100)})
        assert {:error, %Error{c03: 0x0D, reason: {:c14, _}}} = open(ctx, bad_c14)

        # Encrypted for another key, with the recipient fields rewritten.
        {:ok, to_c} = Sinetex.seal(@content, from: ctx.a, to: ctx.cert_c, version: version)
        rewritten = tamper_header(to_c, &%{&1 | c11: ctx.cert_b.serial_field})
        assert c03(open(ctx, rewritten)) == 0x0D
      end
    end

    test "0x0D becomes 0x0E with c14_errors: :uniform", ctx do
      for version <- [2, 3] do
        envelope = seal!(ctx, @content, version: version)
        bad_c14 = tamper_header(envelope, &%{&1 | c14: flip_byte(&1.c14, 100)})
        assert {:error, error} = open(ctx, bad_c14, c14_errors: :uniform)
        assert error.c03 == 0x0E
        assert error.egen == "EGEN9914"
        # The real cause stays in the internal reason.
        assert {:c14, _} = error.reason
      end
    end

    test "0x0E symmetric algorithm", ctx do
      envelope = seal!(ctx)
      assert c03(open(ctx, flip_byte(envelope, byte_size(envelope) - 1))) == 0x0E
      assert c03(open(ctx, flip_byte(envelope, 588))) == 0x0E
      # v3 body shorter than the GCM tag.
      assert c03(open(ctx, binary_part(envelope, 0, 588 + 15))) == 0x0E
    end

    test "0x0F v2 body not a multiple of 8", ctx do
      envelope = seal!(ctx, @content, version: 2)
      assert c03(open(ctx, envelope <> "x")) == 0x0F
      assert c03(open(ctx, binary_part(envelope, 0, byte_size(envelope) - 1))) == 0x0F
    end

    test "0x10, 0x11 and 0x14 come from :certificate_check", ctx do
      envelope = seal!(ctx)

      for code <- [0x10, 0x11, 0x14] do
        check = fn %Sinetex.Certificate{} = cert, %Header{} ->
          assert cert == ctx.cert_a
          {:error, code}
        end

        assert c03(open(ctx, envelope, certificate_check: check)) == code
      end

      assert {:ok, _} = open(ctx, envelope, certificate_check: fn _, _ -> :ok end)

      # C04 1: the sender says its certificate is not activated yet.
      pending = seal!(ctx, @content, c04: 1)
      check = fn _cert, header -> if header.c04 == 1, do: :ok, else: {:error, 0x10} end
      assert {:ok, _} = open(ctx, pending, certificate_check: check)
    end

    test ":certificate_check must return :ok or a C03 code", ctx do
      envelope = seal!(ctx)

      assert_raise ArgumentError, fn ->
        open(ctx, envelope, certificate_check: fn _, _ -> :nope end)
      end

      assert_raise ArgumentError, fn ->
        open(ctx, envelope, certificate_check: fn _, _ -> {:error, 0x99} end)
      end
    end

    test "0x12 generic: decompression", ctx do
      not_gzip = <<0x1F, 0x8B>> <> "definitely not deflate"
      envelope = seal!(ctx, not_gzip, c04: 4) |> tamper_header(&%{&1 | c04: 8})
      assert {:error, %Error{c03: 0x12, reason: {:decompression, _}}} = open(ctx, envelope)

      bomb = seal!(ctx, :binary.copy(<<0>>, 2_000_000), c04: 8, compression: :gzip)

      assert {:error, %Error{c03: 0x12, reason: {:decompression, :output_too_large}}} =
               open(ctx, bomb, max_output_bytes: 1_000_000)

      assert {:ok, _} = open(ctx, bomb, max_output_bytes: 2_000_000)
    end

    test "0x12 generic: input limit", ctx do
      envelope = seal!(ctx)

      assert {:error, %Error{c03: 0x12, reason: :input_too_large}} =
               open(ctx, envelope, max_input_bytes: byte_size(envelope) - 1)

      assert {:ok, _} = open(ctx, envelope, max_input_bytes: byte_size(envelope))
    end

    test "0x13 special treatment indicator", ctx do
      envelope = seal!(ctx)

      for v <- [5, 7, 9, 11, 0xFF],
          do: assert(c03(open(ctx, tamper_header(envelope, &%{&1 | c04: v}))) == 0x13)
    end
  end

  describe "lowest code wins (§5.5.3)" do
    test "the lowest of the header errors is reported, all of them in the reason", ctx do
      envelope = seal!(ctx)
      tampered = tamper_header(envelope, &%{&1 | c09: 2, c04: 7, c13: ctx.cert_c.serial_field})

      assert {:error, %Error{c03: 0x06, reason: {:header, [0x06, 0x0A, 0x13]}}} =
               open(ctx, tampered)

      tampered = tamper_header(envelope, &%{&1 | c02: 9, c08: 1})
      assert {:error, %Error{c03: 0x02, reason: {:header, [0x02, 0x05]}}} = open(ctx, tampered)
    end

    test "inspect shows the codes of the reason as numbers", ctx do
      envelope = seal!(ctx)
      c11_c13 = ctx.cert_c.serial_field
      {:error, error} = open(ctx, tamper_header(envelope, &%{&1 | c11: c11_c13, c13: c11_c13}))
      assert error.reason == {:header, [0x08, 0x0A]}
      assert inspect(error) =~ "reason: {:header, [8, 10]}"
    end

    test "header errors come before cryptography", ctx do
      envelope = seal!(ctx)
      tampered = envelope |> flip_byte(600) |> tamper_header(&%{&1 | c04: 9})
      assert c03(open(ctx, tampered)) == 0x13
    end
  end

  describe "empty header (§5.6.3)" do
    @empty <<588::16, 0::size(586 * 8)>>

    test "rejected by default", ctx do
      assert {:error, %Error{c03: 0x02, reason: :clear_not_allowed}} = open(ctx, @empty <> "echo")
    end

    test "clear content with allow_clear: true", ctx do
      assert {:ok, %Opened{content: "echo", protection: :clear, sender: nil}} =
               open(ctx, @empty <> "echo", allow_clear: true)
    end

    test "C11 and C13 may hold the serial number zero as text", ctx do
      zeros = String.duplicate("0", 32)

      for {c11, c13} <- [{zeros, zeros}, {zeros, <<0::256>>}, {<<0::256>>, zeros}] do
        envelope = tamper_header(@empty, &%{&1 | c11: c11, c13: c13}) <> "echo"

        assert {:ok, %Opened{content: "echo", protection: :clear}} =
                 open(ctx, envelope, allow_clear: true)

        assert {:error, %Error{c03: 0x02, reason: :clear_not_allowed}} = open(ctx, envelope)
      end
    end

    test "a header with zeros and C02 = 0 that is not entirely empty is invalid", ctx do
      assert c03(open(ctx, tamper_header(@empty, &%{&1 | c04: 2}), allow_clear: true)) == 0x02
    end
  end

  describe "pc_check: :ignore" do
    test "C10 and C12 are not compared with the certificates", ctx do
      envelope = tamper_header(seal!(ctx), &%{&1 | c10: 1, c12: 2})
      assert c03(open(ctx, envelope)) == 0x07

      assert {:ok, %Opened{content: @content, sender: sender}} =
               open(ctx, envelope, pc_check: :ignore)

      assert sender == ctx.cert_a
    end

    test "the other checks stay", ctx do
      envelope = seal!(ctx)
      ignore = [pc_check: :ignore]
      other = ctx.cert_c.serial_field

      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c11: other}), ignore)) == 0x08
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c13: other}), ignore)) == 0x0A
      assert c03(open(ctx, tamper_header(envelope, &%{&1 | c13: <<0::256>>}), ignore)) == 0x0A
      assert c03(open(ctx, envelope, [from: ctx.cert_c] ++ ignore)) == 0x0A

      {:ok, by_c} = Sinetex.seal(@content, from: identity("bank_c"), to: ctx.cert_b)
      assert c03(open(ctx, by_c, [known: [ctx.cert_c]] ++ ignore)) == 0x0C
      forged = tamper_header(by_c, &%{&1 | c13: ctx.cert_a.serial_field})
      assert c03(open(ctx, forged, ignore)) == 0x0B
    end

    test "C12 breaks a tie between senders with the same serial number", ctx do
      # bank_b and twin_b have the same serial number and different PCs.
      {:ok, by_b} = Sinetex.seal(@content, from: ctx.b, to: ctx.cert_a)
      opts = [as: ctx.a, from: [certificate("twin_b", pc: 4), ctx.cert_b], pc_check: :ignore]

      assert {:ok, %Opened{sender: sender}} = Sinetex.open(by_b, opts)
      assert sender == ctx.cert_b

      # C12 matches neither: the sender is ambiguous.
      no_match = tamper_header(by_b, &%{&1 | c12: 1})
      assert c03(Sinetex.open(no_match, opts)) == 0x09

      # The same certificate twice is not a tie.
      assert {:ok, _} = Sinetex.open(no_match, Keyword.put(opts, :from, [ctx.cert_b, ctx.cert_b]))
    end
  end

  describe "error_envelope/2" do
    test "signed only, C04 3, with C03", ctx do
      {:ok, envelope} =
        Sinetex.error_envelope("<GEN0004/>", from: ctx.a, to: ctx.cert_b, c03: 0x0B)

      {:ok, header, body} = Header.decode(envelope)
      assert {header.c03, header.c04, header.c14} == {0x0B, 3, <<0::2048>>}
      assert body == "<GEN0004/>"

      # Opened like any other; the code is in the header (§5.5.5).
      assert {:ok, %Opened{protection: :signed, content: "<GEN0004/>"} = opened} =
               open(ctx, envelope)

      assert opened.header.c03 == 0x0B
    end

    test "0xFF and v2", ctx do
      {:ok, envelope} =
        Sinetex.error_envelope("x", from: ctx.a, to: ctx.cert_b, c03: 0xFF, version: 2)

      assert {:ok, %{header: %{c03: 0xFF, c02: 2}}} = open(ctx, envelope)
    end

    test "invalid options raise", ctx do
      assert_raise ArgumentError, fn -> Sinetex.error_envelope("x", from: ctx.a, c03: 0) end
      assert_raise ArgumentError, fn -> Sinetex.error_envelope("x", from: ctx.a, c03: 0x15) end

      assert_raise ArgumentError, fn ->
        Sinetex.error_envelope("x", from: ctx.a, c03: 1, c04: 0)
      end
    end
  end

  describe "open/2 options" do
    test "invalid options raise", ctx do
      envelope = seal!(ctx)

      for bad <- [
            [as: nil],
            [from: []],
            [from: [:x]],
            [known: :x],
            [c14_errors: :other],
            [trim_padding: 1],
            [allow_clear: nil],
            [pc_check: :lenient],
            [max_output_bytes: 0],
            [max_input_bytes: -1],
            [certificate_check: fn _ -> :ok end],
            [unknown: 1]
          ] do
        assert_raise ArgumentError, fn -> open(ctx, envelope, bad) end
      end
    end

    test "inspect of the result leaves the content out", ctx do
      {:ok, opened} = open(ctx, seal!(ctx, "secret content"))
      refute inspect(opened) =~ "secret"
    end
  end
end
