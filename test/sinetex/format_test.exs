defmodule Sinetex.FormatTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sinetex.{Error, Header, Serial}

  doctest Sinetex.Serial
  doctest Sinetex.Error

  describe "Serial" do
    test "manual examples (§5.2.6)" do
      assert Serial.encode(0x5D77DA7B6F02EFA1EDDA741E78FF3508) ==
               {:ok, "5D77DA7B6F02EFA1EDDA741E78FF3508"}

      assert Serial.encode(0x3B3BC056) == {:ok, "0000000000000000000000003B3BC056"}
    end

    test "limits" do
      assert Serial.encode(0) == {:ok, String.duplicate("0", 32)}
      assert Serial.encode(Bitwise.bsl(1, 128) - 1) == {:ok, String.duplicate("F", 32)}
      assert Serial.encode(Bitwise.bsl(1, 128)) == {:error, :serial_too_long}
      assert Serial.encode(-1) == {:error, :invalid_serial}
    end

    test "valid?/1" do
      refute Serial.valid?(String.duplicate("0", 31))
      refute Serial.valid?(String.duplicate("G", 32))
      refute Serial.valid?(<<0::256>>)
      refute Serial.valid?(nil)
    end

    property "encoded serials are valid and decode back" do
      check all serial <- integer(0..(Bitwise.bsl(1, 128) - 1)) do
        assert {:ok, field} = Serial.encode(serial)
        assert Serial.valid?(field)
        assert String.to_integer(field, 16) == serial
      end
    end
  end

  describe "Header" do
    test "encodes 588 bytes with fields at the manual's offsets" do
      header = %Header{
        c02: 3,
        c03: 0x0B,
        c04: 8,
        c06: 2,
        c07: 2,
        c08: 2,
        c09: 3,
        c10: 6,
        c11: "0000000000000000000000003B3BC056",
        c12: 4,
        c13: "5D77DA7B6F02EFA1EDDA741E78FF3508",
        c14: :binary.copy(<<0xAA>>, 256),
        c15: :binary.copy(<<0xBB>>, 256)
      }

      bin = Header.encode(header)
      assert byte_size(bin) == 588
      # Positions are 1-based in the manual.
      at = fn pos, len -> binary_part(bin, pos - 1, len) end
      assert at.(1, 2) == <<0x02, 0x4C>>
      assert at.(3, 1) == <<3>>
      assert at.(4, 1) == <<0x0B>>
      assert at.(5, 1) == <<8>>
      assert at.(6, 1) == <<0>>
      assert at.(7, 4) == <<2, 2, 2, 3>>
      assert at.(11, 1) == <<6>>
      assert at.(12, 32) == "0000000000000000000000003B3BC056"
      assert at.(44, 1) == <<4>>
      assert at.(45, 32) == "5D77DA7B6F02EFA1EDDA741E78FF3508"
      assert at.(77, 256) == :binary.copy(<<0xAA>>, 256)
      assert at.(333, 256) == :binary.copy(<<0xBB>>, 256)

      assert {:ok, ^header, "body"} = Header.decode(bin <> "body")
    end

    test "decode/1 needs 588 bytes" do
      assert Header.decode(<<0::587*8>>) == {:error, :too_short}
      assert {:ok, %Header{}, ""} = Header.decode(<<0::588*8>>)
    end

    test "empty?/1" do
      assert Header.empty?(%Header{})
      refute Header.empty?(%Header{c02: 3})
      refute Header.empty?(%Header{c11: "0000000000000000000000003B3BC056"})
      # The serial number zero as text (§5.1.4) also counts as zero.
      zeros = String.duplicate("0", 32)
      assert Header.empty?(%Header{c11: zeros, c13: zeros})
      assert Header.empty?(%Header{c13: zeros})
      refute Header.empty?(%Header{c11: zeros, c13: zeros, c04: 2})
    end

    test "encode/1 rejects fields of the wrong size" do
      assert_raise ArgumentError, fn -> Header.encode(%Header{c11: "short"}) end
      assert_raise ArgumentError, fn -> Header.encode(%Header{c02: 256}) end
    end

    test "inspect shows the fields and hides C14/C15" do
      inspected = inspect(%Header{c02: 3, c14: :binary.copy(<<1>>, 256)})
      assert inspected =~ "#Sinetex.Header<"
      assert inspected =~ "c02: 0x03"
      assert inspected =~ "c14: 256 bytes"
      assert inspected =~ "c15: zero"
    end

    property "decode(encode(h)) == h" do
      check all fields <- fixed_list(Enum.map(1..10, fn _ -> integer(0..255) end)),
                c11 <- binary(length: 32),
                c13 <- binary(length: 32),
                c14 <- binary(length: 256),
                c15 <- binary(length: 256),
                body <- binary() do
        [c02, c03, c04, c05, c06, c07, c08, c09, c10, c12] = fields

        header = %Header{
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

        assert {:ok, ^header, ^body} = Header.decode(Header.encode(header) <> body)
      end
    end
  end

  describe "Error" do
    test "table of §5.5.1" do
      assert Error.codes() == Enum.to_list(0x01..0x14) ++ [0xFF]

      for code <- 0x01..0x14 do
        error = Error.new(code)
        assert error.egen == "EGEN99" <> String.pad_leading(Integer.to_string(code), 2, "0")
      end

      assert %Error{egen: nil} = Error.new(0xFF)
      assert_raise ArgumentError, fn -> Error.new(0x15) end
      assert_raise ArgumentError, fn -> Error.new(0) end
    end

    test "message/1" do
      assert Exception.message(Error.new(0x0D)) ==
               "EGEN9913 (C03 0x0D): could not extract the symmetric key"

      assert Exception.message(Error.new(0xFF)) == "C03 0xFF: error outside the security scope"
    end
  end
end
