defmodule Sinetex.Identity do
  @moduledoc """
  Your own certificate and its RSA private key.

  An identity signs what you send (`from:` in `Sinetex.seal/2`) and decrypts
  what you receive (`as:` in `Sinetex.open/2`).

  The private key is loaded from PEM (PKCS#1 or PKCS#8, optionally encrypted)
  or DER. Keeping the key safe (HSM, vault, file permissions) is up to the
  caller. The struct does not show the key when inspected.
  """

  require Record

  Record.defrecordp(
    :rsa_private_key,
    :RSAPrivateKey,
    Record.extract(:RSAPrivateKey, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :rsa_public_key,
    :RSAPublicKey,
    Record.extract(:RSAPublicKey, from_lib: "public_key/include/public_key.hrl")
  )

  @enforce_keys [:certificate, :private_key]
  @derive {Inspect, only: [:certificate]}
  defstruct [:certificate, :private_key]

  @type t :: %__MODULE__{
          certificate: Sinetex.Certificate.t(),
          private_key: :public_key.rsa_private_key()
        }

  @type load_error :: Sinetex.Certificate.load_error() | :invalid_private_key | :key_mismatch

  @doc """
  Loads a certificate and its private key.

  Both are binaries in PEM or DER. The certificate goes through the checks of
  `Sinetex.Certificate.load/2`, and the key must match the certificate.

  ## Options

    * `:pc` and `:serial` - see `Sinetex.Certificate.load/2`.
    * `:password` - password of an encrypted PEM key.

  ## Examples

      {:ok, me} = Sinetex.Identity.load(File.read!("me.pem"), File.read!("me.key"))
      {:ok, me} = Sinetex.Identity.load(cert, key, pc: 0x06, password: "secret")
  """
  @spec load(binary(), binary(), keyword()) :: {:ok, t()} | {:error, load_error()}
  def load(cert, key, opts \\ []) when is_binary(cert) and is_binary(key) and is_list(opts) do
    opts = Keyword.validate!(opts, [:pc, :serial, :password])

    with {:ok, certificate} <- Sinetex.Certificate.load(cert, Keyword.take(opts, [:pc, :serial])),
         {:ok, private_key} <- decode_key(key, opts[:password]),
         :ok <- check_match(certificate, private_key) do
      {:ok, %__MODULE__{certificate: certificate, private_key: private_key}}
    end
  end

  defp decode_key(key, password) do
    if String.contains?(key, "-----BEGIN") do
      key
      |> Sinetex.Certificate.safe_pem_decode()
      |> Enum.find(&(elem(&1, 0) in [:RSAPrivateKey, :PrivateKeyInfo, :EncryptedPrivateKeyInfo]))
      |> decode_pem_entry(password)
    else
      decode_der(key)
    end
  end

  defp decode_pem_entry(nil, _password), do: {:error, :invalid_private_key}

  defp decode_pem_entry(entry, password) do
    decoded =
      case {entry, password} do
        {{_, _, :not_encrypted}, _} -> :public_key.pem_entry_decode(entry)
        {_, nil} -> nil
        {_, password} -> :public_key.pem_entry_decode(entry, to_charlist(password))
      end

    rsa_key(decoded)
  rescue
    _ -> {:error, :invalid_private_key}
  catch
    _, _ -> {:error, :invalid_private_key}
  end

  defp decode_der(der) do
    Enum.find_value([:RSAPrivateKey, :PrivateKeyInfo], {:error, :invalid_private_key}, fn type ->
      case safe_der_decode(type, der) do
        {:ok, _} = ok -> ok
        _ -> nil
      end
    end)
  end

  defp safe_der_decode(type, der) do
    rsa_key(:public_key.der_decode(type, der))
  rescue
    _ -> {:error, :invalid_private_key}
  catch
    _, _ -> {:error, :invalid_private_key}
  end

  defp rsa_key(rsa_private_key() = key), do: {:ok, key}
  defp rsa_key(_), do: {:error, :invalid_private_key}

  defp check_match(certificate, rsa_private_key(modulus: n, publicExponent: e)) do
    case certificate.public_key do
      rsa_public_key(modulus: ^n, publicExponent: ^e) -> :ok
      _ -> {:error, :key_mismatch}
    end
  end
end
