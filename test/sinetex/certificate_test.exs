defmodule Sinetex.CertificateTest do
  use ExUnit.Case, async: true

  import Sinetex.Fixtures, only: [read!: 1, certificate: 1]
  alias Sinetex.{Certificate, Identity}

  describe "Certificate.load/2" do
    test "PEM, with the PC derived from OU=CSPB-n in the issuer" do
      assert {:ok, cert} = Certificate.load(read!("bank_a.crt"))
      assert cert.serial == 0x5D77DA7B6F02EFA1EDDA741E78FF3508
      assert cert.serial_field == "5D77DA7B6F02EFA1EDDA741E78FF3508"
      assert cert.pc == 6
      assert cert.key_bits == 2048
      assert cert.subject == "C=BR, O=Bank A, CN=bank-a.test"
      assert cert.issuer =~ "OU=CSPB-6"
      assert %DateTime{} = cert.not_before
      assert DateTime.compare(cert.not_after, cert.not_before) == :gt
    end

    test "DER" do
      assert {:ok, der} = Certificate.load(read!("bank_a.crt.der"))
      assert {:ok, pem} = Certificate.load(read!("bank_a.crt"))
      assert der == pem
    end

    test "short serial is left-padded with '0'" do
      assert {:ok, %{serial_field: "0000000000000000000000003B3BC056"}} =
               Certificate.load(read!("bank_b.crt"))
    end

    test "explicit :pc wins over the derived one" do
      assert {:ok, %{pc: 2}} = Certificate.load(read!("bank_a.crt"), pc: 2)
    end

    test "without OU=CSPB-n the PC must be given" do
      assert Certificate.load(read!("chamber.crt")) == {:error, :pc_code_required}
      assert {:ok, %{pc: 4}} = Certificate.load(read!("chamber.crt"), pc: 4)
    end

    test ":serial replaces the serial number written in C11/C13" do
      {:ok, cert} = Certificate.load(read!("long_serial.crt"), serial: 0x1234)
      assert cert.serial_field == "00000000000000000000000000001234"
      assert cert.serial == 0x0102030405060708090A0B0C0D0E0F1011

      assert {:ok, %{serial_field: "00000000000000000000000000000000"}} =
               Certificate.load(read!("bank_a.crt"), serial: 0)

      assert Certificate.load(read!("bank_a.crt"), serial: Bitwise.bsl(1, 128)) ==
               {:error, :serial_too_long}
    end

    test "rejects keys and serials the protocol cannot carry" do
      assert Certificate.load(read!("long_serial.crt")) == {:error, :serial_too_long}
      assert Certificate.load(read!("e3.crt")) == {:error, {:invalid_public_exponent, 3}}
      assert Certificate.load(read!("rsa1024.crt")) == {:error, {:unsupported_key_size, 1024}}
      assert Certificate.load(read!("ec.crt")) == {:error, :not_rsa}
    end

    test "rejects garbage" do
      assert Certificate.load("") == {:error, :invalid_certificate}
      assert Certificate.load("not a certificate") == {:error, :invalid_certificate}

      assert Certificate.load("-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n") ==
               {:error, :invalid_certificate}

      assert Certificate.load(read!("bank_a.key")) == {:error, :invalid_certificate}

      assert Certificate.load(binary_part(read!("bank_a.crt.der"), 0, 100)) ==
               {:error, :invalid_certificate}
    end

    test "invalid options raise" do
      assert_raise ArgumentError, fn -> Certificate.load(read!("bank_a.crt"), pc: 0) end
      assert_raise ArgumentError, fn -> Certificate.load(read!("bank_a.crt"), pc: 256) end
      assert_raise ArgumentError, fn -> Certificate.load(read!("bank_a.crt"), foo: 1) end
      assert_raise ArgumentError, fn -> Certificate.load(read!("bank_a.crt"), serial: -1) end
      assert_raise ArgumentError, fn -> Certificate.load(read!("bank_a.crt"), serial: "1") end
    end

    test "inspect" do
      {:ok, cert} = Certificate.load(read!("bank_b.crt"))

      assert inspect(cert) ==
               ~s(#Sinetex.Certificate<serial: 0000000000000000000000003B3BC056, pc: 6, subject: "C=BR, O=Bank B, CN=bank-b.test">)
    end
  end

  describe "Identity.load/3" do
    test "every key encoding" do
      cert = read!("bank_a.crt")

      for key <- ["bank_a.key", "bank_a.pkcs1.pem", "bank_a.pkcs8.der", "bank_a.pkcs1.der"] do
        assert {:ok, %Identity{certificate: %{pc: 6}}} = Identity.load(cert, read!(key)), key
      end
    end

    test "encrypted key" do
      cert = read!("bank_a.crt")
      key = read!("bank_a.encrypted.key")
      assert {:ok, _} = Identity.load(cert, key, password: "test-password")
      assert Identity.load(cert, key, password: "wrong") == {:error, :invalid_private_key}
      assert Identity.load(cert, key) == {:error, :invalid_private_key}
    end

    test "key must match the certificate" do
      assert Identity.load(read!("bank_a.crt"), read!("bank_b.key")) == {:error, :key_mismatch}
    end

    test "certificate errors come first" do
      assert Identity.load(read!("chamber.crt"), read!("chamber.key")) ==
               {:error, :pc_code_required}

      assert {:ok, _} = Identity.load(read!("chamber.crt"), read!("chamber.key"), pc: 4)
    end

    test ":serial" do
      cert = read!("long_serial.crt")
      key = read!("long_serial.key")
      assert Identity.load(cert, key) == {:error, :serial_too_long}

      assert {:ok, %Identity{certificate: %{serial_field: "0000000000000000000000000000ABCD"}}} =
               Identity.load(cert, key, serial: 0xABCD)
    end

    test "a PKCS#12 file converted with the commands of the guide" do
      assert {:ok, me} =
               Identity.load(read!("bank_a.from_p12.crt"), read!("bank_a.from_p12.key"),
                 password: "test-password"
               )

      assert me.certificate == certificate("bank_a")
    end

    test "garbage key" do
      assert Identity.load(read!("bank_a.crt"), "nope") == {:error, :invalid_private_key}

      assert Identity.load(read!("bank_a.crt"), read!("bank_a.crt")) ==
               {:error, :invalid_private_key}
    end

    test "inspect does not show the private key" do
      {:ok, me} = Identity.load(read!("bank_a.crt"), read!("bank_a.key"))
      inspected = inspect(me, limit: :infinity, printable_limit: :infinity)
      assert inspected =~ "#Sinetex.Identity<"
      refute inspected =~ "private_key"
      refute inspected =~ "RSAPrivateKey"
    end
  end
end
