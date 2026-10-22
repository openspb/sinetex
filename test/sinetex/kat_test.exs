defmodule Sinetex.KATTest do
  # Known-answer tests: with a deterministic generator, every byte of the
  # envelope except C14 (RSAES-PKCS1-v1_5 adds its own random padding) is
  # predictable and is recomputed here from the primitives, independently of
  # the library code.
  use ExUnit.Case, async: true

  import Sinetex.Fixtures
  alias Sinetex.Header

  @content "<DOC>known answer</DOC>"

  setup do
    on_exit(&uninstall_rng/0)
    %{a: identity("bank_a"), b: identity("bank_b")}
  end

  defp expected_rng(seed, n) do
    install_rng(seed)
    bytes = Sinetex.Random.bytes(n)
    uninstall_rng()
    bytes
  end

  test "the deterministic generator repeats its output" do
    assert expected_rng("seed", 40) == expected_rng("seed", 40)
    refute expected_rng("seed", 40) == expected_rng("other", 40)
    # Without it, the library uses :crypto.strong_rand_bytes/1.
    refute Sinetex.Random.bytes(40) == Sinetex.Random.bytes(40)
  end

  test "v3: K ‖ N from the generator, AES-256-GCM body, deterministic signature", ctx do
    <<key::binary-32, nonce::binary-12>> = expected_rng("kat-v3", 44)

    install_rng("kat-v3")
    {:ok, envelope} = Sinetex.seal(@content, from: ctx.a, to: ctx.b.certificate)
    {:ok, header, body} = Header.decode(envelope)

    # C14 carries K ‖ N, encrypted for the recipient.
    assert :public_key.decrypt_private(header.c14, ctx.b.private_key) == key <> nonce

    # Body = ciphertext ‖ tag, without associated data.
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, @content, <<>>, true)

    assert body == ciphertext <> tag

    # RSASSA-PKCS1-v1_5 is deterministic: same bytes as :public_key.sign/3.
    assert header.c15 == :public_key.sign(@content, :sha256, ctx.a.private_key)
  end

  test "v2: odd-parity key, IV = first 8 bytes, zero padding before signing", ctx do
    raw = expected_rng("kat-v2", 24)
    key = Sinetex.Crypto.odd_parity(raw)
    <<iv::binary-8, _::binary>> = key

    install_rng("kat-v2")
    {:ok, envelope} = Sinetex.seal(@content, from: ctx.a, to: ctx.b.certificate, version: 2)
    {:ok, header, body} = Header.decode(envelope)

    assert :public_key.decrypt_private(header.c14, ctx.b.private_key) == key

    padded = @content <> :binary.copy(<<0>>, 8 - rem(byte_size(@content), 8))
    assert rem(byte_size(padded), 8) == 0
    assert body == :crypto.crypto_one_time(:des_ede3_cbc, key, iv, padded, true)
    assert header.c15 == :public_key.sign(padded, :sha256, ctx.a.private_key)
  end

  test "odd parity" do
    assert Sinetex.Crypto.odd_parity(<<0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF, 0x80, 0x7F>>) ==
             <<0x01, 0x01, 0x02, 0x02, 0xFE, 0xFE, 0x80, 0x7F>>

    for <<b <- Sinetex.Crypto.odd_parity(:crypto.strong_rand_bytes(1000))>> do
      ones = for(<<(bit::1 <- <<b>>)>>, do: bit) |> Enum.sum()
      assert rem(ones, 2) == 1
    end
  end

  test "chunked SHA-256 matches :crypto.hash/2" do
    for size <- [0, 1, 1_048_575, 1_048_576, 1_048_577, 3 * 1_048_576 + 5] do
      data = :binary.copy(<<size::32>>, div(size, 4)) <> binary_part(<<1, 2, 3>>, 0, rem(size, 4))
      assert Sinetex.Crypto.sha256(data) == :crypto.hash(:sha256, data)
    end
  end

  test "PKCS#1 v1.5 decoding of C14 is done by the library", ctx do
    pub = ctx.b.certificate.public_key
    msg = :crypto.strong_rand_bytes(44)

    assert {:ok, ^msg} =
             Sinetex.Crypto.unwrap_key(
               :public_key.encrypt_public(msg, pub),
               ctx.b.private_key,
               44
             )

    # Wrong length inside a valid encoding.
    short = :public_key.encrypt_public(:crypto.strong_rand_bytes(24), pub)

    assert {:error, :c14_bad_encoding, fake} =
             Sinetex.Crypto.unwrap_key(short, ctx.b.private_key, 44)

    assert byte_size(fake) == 44

    # Not an RSA ciphertext for this key (value >= modulus).
    assert {:error, :c14_rsa_failed, _} =
             Sinetex.Crypto.unwrap_key(:binary.copy(<<0xFF>>, 256), ctx.b.private_key, 24)
  end
end
