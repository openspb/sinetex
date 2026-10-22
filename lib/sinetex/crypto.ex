defmodule Sinetex.Crypto do
  @moduledoc false

  # Cryptographic primitives of the protocol, on top of :crypto and :public_key.

  @chunk 1_048_576
  @modulus_bytes 256

  ## Hash and signature (C09, C15)

  # SHA-256 in 1 MiB chunks, so that hashing a large payload does not hold a
  # scheduler for the whole computation.
  @spec sha256(binary()) :: binary()
  def sha256(data) when byte_size(data) <= @chunk, do: :crypto.hash(:sha256, data)
  def sha256(data), do: hash_chunks(:crypto.hash_init(:sha256), data, 0)

  defp hash_chunks(ctx, data, offset) when byte_size(data) - offset > @chunk do
    ctx = :crypto.hash_update(ctx, binary_part(data, offset, @chunk))
    hash_chunks(ctx, data, offset + @chunk)
  end

  defp hash_chunks(ctx, data, offset) do
    ctx
    |> :crypto.hash_update(binary_part(data, offset, byte_size(data) - offset))
    |> :crypto.hash_final()
  end

  @spec sign(binary(), :public_key.rsa_private_key()) :: <<_::2048>>
  def sign(data, private_key) do
    :public_key.sign({:digest, sha256(data)}, :sha256, private_key)
  end

  @spec verify?(binary(), binary(), :public_key.rsa_public_key()) :: boolean()
  def verify?(data, signature, public_key) do
    :public_key.verify({:digest, sha256(data)}, :sha256, signature, public_key)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  ## Key transport (C14)

  @spec wrap_key(binary(), :public_key.rsa_public_key()) :: <<_::2048>>
  def wrap_key(key_material, public_key) do
    :public_key.encrypt_public(key_material, public_key, rsa_padding: :rsa_pkcs1_padding)
  end

  # Decrypts C14 and removes the RSAES-PKCS1-v1_5 encoding (RFC 8017 §7.2.2)
  # here instead of in OpenSSL. OpenSSL 3.2+ answers a bad encoding with a
  # synthetic message ("implicit rejection") where older versions return an
  # error; doing the decoding here gives the same result on every version.
  #
  # On failure, returns random key material of the expected size, so that
  # the caller goes through the same steps as with a good key.
  @spec unwrap_key(binary(), :public_key.rsa_private_key(), pos_integer()) ::
          {:ok, binary()} | {:error, atom(), binary()}
  def unwrap_key(c14, private_key, size) do
    em =
      try do
        :public_key.decrypt_private(c14, private_key, rsa_padding: :rsa_no_padding)
      rescue
        _ -> :error
      catch
        _, _ -> :error
      end

    case pkcs1_decode(em, size) do
      {:ok, key_material} -> {:ok, key_material}
      {:error, reason} -> {:error, reason, :crypto.strong_rand_bytes(size)}
    end
  end

  defp pkcs1_decode(em, size) when is_binary(em) and byte_size(em) == @modulus_bytes do
    ps_size = @modulus_bytes - 3 - size
    head = binary_part(em, 0, 2)
    ps = binary_part(em, 2, ps_size)
    sep = :binary.at(em, 2 + ps_size)
    m = binary_part(em, 3 + ps_size, size)
    # Evaluate every condition, without short-circuiting.
    ok = [head == <<0, 2>>, :binary.match(ps, <<0>>) == :nomatch, sep == 0]
    if Enum.all?(ok), do: {:ok, m}, else: {:error, :c14_bad_encoding}
  end

  defp pkcs1_decode(_em, _size), do: {:error, :c14_rsa_failed}

  ## Symmetric ciphers

  @spec aes_gcm_encrypt(<<_::256>>, <<_::96>>, binary()) :: binary()
  def aes_gcm_encrypt(key, nonce, data) do
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, data, <<>>, 16, true)

    ciphertext <> tag
  end

  # `body` is ciphertext ‖ tag, at least 16 bytes.
  @spec aes_gcm_decrypt(binary(), binary(), binary()) :: {:ok, binary()} | :error
  def aes_gcm_decrypt(key, nonce, body) do
    size = byte_size(body) - 16
    ciphertext = binary_part(body, 0, size)
    tag = binary_part(body, size, 16)

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, ciphertext, <<>>, tag, false) do
      data when is_binary(data) -> {:ok, data}
      :error -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  # 3DES-EDE3-CBC with IV = first 8 bytes of the key (Annex A, notes 1-2).
  # `data` must be a multiple of 8 bytes: the caller pads it.
  @spec des3_encrypt(<<_::192>>, binary()) :: binary()
  def des3_encrypt(<<iv::binary-8, _::binary-16>> = key, data)
      when rem(byte_size(data), 8) == 0 do
    :crypto.crypto_one_time(:des_ede3_cbc, key, iv, data, true)
  end

  @spec des3_decrypt(<<_::192>>, binary()) :: {:ok, binary()} | :error
  def des3_decrypt(<<iv::binary-8, _::binary-16>> = key, data)
      when rem(byte_size(data), 8) == 0 do
    {:ok, :crypto.crypto_one_time(:des_ede3_cbc, key, iv, data, false)}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @spec des3_available?() :: boolean()
  def des3_available? do
    :des_ede3_cbc in :crypto.supports(:ciphers)
  end

  # Sets odd parity on each byte of a DES key (§5.1.2.1).
  @spec odd_parity(binary()) :: binary()
  def odd_parity(key) do
    for <<b <- key>>, into: <<>> do
      high = Bitwise.band(b, 0xFE)
      ones = for(i <- 1..7, Bitwise.band(Bitwise.bsr(high, i), 1) == 1, do: 1) |> length()
      <<high + if(rem(ones, 2) == 0, do: 1, else: 0)>>
    end
  end
end
