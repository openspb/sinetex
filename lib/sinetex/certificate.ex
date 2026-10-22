defmodule Sinetex.Certificate do
  @moduledoc """
  An X.509 certificate as seen by the protocol: its serial number (C11/C13),
  its certification authority code (C10/C12) and its RSA public key.

  Load the counterparty's certificate with `load/2`. Your own certificate is
  loaded together with its private key by `Sinetex.Identity.load/3`.

  ## Certification authority code (PC)

  Fields C10 and C12 carry the code of the certification authority ("PC")
  that issued the certificate (§5.1, Table 1):

  | Code | PC |
  |---:|---|
  | `0x01` | SPB-Serpro |
  | `0x02` | SPB-Certisign |
  | `0x03` | Pessoas Físicas (STR-WEB only) |
  | `0x04` | SPB-Serasa |
  | `0x05` | SPB-CAIXA |
  | `0x06` | SPB-Valid |
  | `0x07` | SPB-Soluti |

  SPB-style certificates carry `OU=CSPB-n` in their issuer (§4.2.6), where
  `n` is the code, and `load/2` derives the code from it. Certificates without
  it need the `:pc` option; otherwise loading fails with
  `{:error, :pc_code_required}`. An explicit `:pc` always wins over the
  derived code. The library never guesses the code from the issuer's name.

  ## Checks on load

    * RSA key of exactly 2048 bits (§4.4.16), which also means that the most
      significant bit of the modulus is set (§4.2.8);
    * public exponent other than 3 (§4.2.7);
    * serial number of at most 16 bytes, so that it fits C11/C13.
  """

  require Record

  @hrl "public_key/include/public_key.hrl"
  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: @hrl)
  )

  Record.defrecordp(:tbs, :OTPTBSCertificate, Record.extract(:OTPTBSCertificate, from_lib: @hrl))

  Record.defrecordp(
    :spki,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: @hrl)
  )

  Record.defrecordp(
    :algorithm,
    :PublicKeyAlgorithm,
    Record.extract(:PublicKeyAlgorithm, from_lib: @hrl)
  )

  Record.defrecordp(:rsa_public_key, :RSAPublicKey, Record.extract(:RSAPublicKey, from_lib: @hrl))

  Record.defrecordp(
    :attribute,
    :AttributeTypeAndValue,
    Record.extract(:AttributeTypeAndValue, from_lib: @hrl)
  )

  Record.defrecordp(:validity, :Validity, Record.extract(:Validity, from_lib: @hrl))

  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @organizational_unit {2, 5, 4, 11}

  @key_bits 2048

  @enforce_keys [:der, :serial, :serial_field, :pc, :public_key]
  defstruct [
    :der,
    :serial,
    :serial_field,
    :pc,
    :public_key,
    :subject,
    :issuer,
    :not_before,
    :not_after,
    key_bits: @key_bits
  ]

  @typedoc "A certification authority code, as written in C10/C12."
  @type pc :: 1..255

  @type t :: %__MODULE__{
          der: binary(),
          serial: non_neg_integer(),
          serial_field: <<_::256>>,
          pc: pc(),
          public_key: :public_key.rsa_public_key(),
          key_bits: 2048,
          subject: String.t(),
          issuer: String.t(),
          not_before: DateTime.t() | nil,
          not_after: DateTime.t() | nil
        }

  @type load_error ::
          :invalid_certificate
          | :not_rsa
          | {:unsupported_key_size, pos_integer()}
          | {:invalid_public_exponent, integer()}
          | :serial_too_long
          | :invalid_serial
          | :pc_code_required

  @doc """
  Loads a certificate from PEM or DER.

  ## Options

    * `:pc` - the certification authority code (1..255) to write in C10/C12.
      Required when the issuer has no `OU=CSPB-n`.

  ## Examples

      {:ok, peer} = Sinetex.Certificate.load(File.read!("peer.pem"))
      {:ok, chamber} = Sinetex.Certificate.load(File.read!("chamber.pem"), pc: 0x04)
  """
  @spec load(binary(), keyword()) :: {:ok, t()} | {:error, load_error()}
  def load(cert, opts \\ []) when is_binary(cert) and is_list(opts) do
    opts = Keyword.validate!(opts, [:pc])
    pc_option = validate_pc!(opts[:pc])

    with {:ok, der} <- to_der(cert),
         {:ok, tbs} <- decode(der),
         {:ok, public_key} <- public_key(tbs),
         {:ok, serial_field} <- Sinetex.Serial.encode(tbs(tbs, :serialNumber)),
         {:ok, pc} <- pc_code(pc_option, tbs(tbs, :issuer)) do
      {not_before, not_after} = validity_dates(tbs(tbs, :validity))

      {:ok,
       %__MODULE__{
         der: der,
         serial: tbs(tbs, :serialNumber),
         serial_field: serial_field,
         pc: pc,
         public_key: public_key,
         subject: format_name(tbs(tbs, :subject)),
         issuer: format_name(tbs(tbs, :issuer)),
         not_before: not_before,
         not_after: not_after
       }}
    end
  end

  @doc false
  @spec validate_pc!(pc() | nil) :: pc() | nil
  def validate_pc!(nil), do: nil
  def validate_pc!(pc) when is_integer(pc) and pc in 1..255, do: pc

  def validate_pc!(pc) do
    raise ArgumentError, "expected :pc to be an integer in 1..255, got: #{inspect(pc)}"
  end

  @doc false
  # Checks an RSA key against the rules of §4.2.7, §4.2.8 and §4.4.16.
  @spec check_rsa_key(pos_integer(), integer()) ::
          :ok
          | {:error,
             {:unsupported_key_size, pos_integer()} | {:invalid_public_exponent, integer()}}
  def check_rsa_key(modulus, exponent) do
    bits = bit_length(modulus)

    cond do
      bits != @key_bits ->
        {:error, {:unsupported_key_size, bits}}

      exponent == 3 or exponent < 3 or rem(exponent, 2) == 0 ->
        {:error, {:invalid_public_exponent, exponent}}

      true ->
        :ok
    end
  end

  defp to_der(cert) do
    if String.contains?(cert, "-----BEGIN") do
      case Enum.find(safe_pem_decode(cert), &match?({:Certificate, _, :not_encrypted}, &1)) do
        {:Certificate, der, :not_encrypted} -> {:ok, der}
        nil -> {:error, :invalid_certificate}
      end
    else
      {:ok, cert}
    end
  end

  @doc false
  @spec safe_pem_decode(binary()) :: [:public_key.pem_entry()]
  def safe_pem_decode(pem) do
    :public_key.pem_decode(pem)
  rescue
    _ -> []
  end

  defp decode(der) do
    case :public_key.pkix_decode_cert(der, :otp) do
      otp_certificate(tbsCertificate: tbs) -> {:ok, tbs}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  catch
    _, _ -> {:error, :invalid_certificate}
  end

  defp public_key(tbs) do
    case tbs(tbs, :subjectPublicKeyInfo) do
      spki(
        algorithm: algorithm(algorithm: @rsa_encryption),
        subjectPublicKey: rsa_public_key(modulus: n, publicExponent: e) = key
      ) ->
        with :ok <- check_rsa_key(n, e), do: {:ok, key}

      _ ->
        {:error, :not_rsa}
    end
  end

  defp pc_code(pc, _issuer) when is_integer(pc), do: {:ok, pc}

  defp pc_code(nil, issuer) do
    derived =
      Enum.find_value(attributes(issuer), fn
        {@organizational_unit, value} -> cspb_code(attribute_string(value))
        _ -> nil
      end)

    if derived, do: {:ok, derived}, else: {:error, :pc_code_required}
  end

  defp cspb_code(ou) do
    with [_, n] <- Regex.run(~r/\ACSPB-(\d{1,3})\z/, ou),
         code when code in 1..255 <- String.to_integer(n) do
      code
    else
      _ -> nil
    end
  end

  defp attributes({:rdnSequence, rdns}) do
    for rdn <- rdns, attribute(type: type, value: value) <- rdn, do: {type, value}
  end

  defp attributes(_), do: []

  @names %{
    {2, 5, 4, 3} => "CN",
    {2, 5, 4, 5} => "serialNumber",
    {2, 5, 4, 6} => "C",
    {2, 5, 4, 7} => "L",
    {2, 5, 4, 8} => "ST",
    {2, 5, 4, 10} => "O",
    {2, 5, 4, 11} => "OU"
  }

  defp format_name(name) do
    name
    |> attributes()
    |> Enum.map_join(", ", fn {type, value} ->
      label = Map.get_lazy(@names, type, fn -> type |> Tuple.to_list() |> Enum.join(".") end)
      "#{label}=#{attribute_string(value)}"
    end)
  end

  @string_tags [
    :utf8String,
    :printableString,
    :teletexString,
    :universalString,
    :bmpString,
    :ia5String
  ]

  defp attribute_string({tag, value}) when tag in @string_tags, do: chars_to_string(value)
  defp attribute_string(value) when is_list(value), do: chars_to_string(value)

  defp attribute_string(value) when is_binary(value) do
    if String.printable?(value), do: value, else: "#" <> Base.encode16(value)
  end

  defp attribute_string(value), do: inspect(value)

  defp chars_to_string(value) do
    if is_binary(value), do: value, else: List.to_string(value)
  rescue
    _ -> inspect(value)
  end

  defp validity_dates(validity(notBefore: not_before, notAfter: not_after)) do
    {parse_time(not_before), parse_time(not_after)}
  end

  defp validity_dates(_), do: {nil, nil}

  defp parse_time({:utcTime, time}) do
    case to_string(time) do
      <<yy::binary-2, rest::binary-10, "Z">> ->
        year = String.to_integer(yy)
        parse_time({:generalTime, "#{if year >= 50, do: 1900 + year, else: 2000 + year}#{rest}Z"})

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  defp parse_time({:generalTime, time}) do
    with <<y::binary-4, mo::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">> <-
           to_string(time),
         {:ok, dt, 0} <- DateTime.from_iso8601("#{y}-#{mo}-#{d}T#{h}:#{mi}:#{s}Z") do
      dt
    else
      _ -> nil
    end
  end

  defp parse_time(_), do: nil

  defp bit_length(n) when is_integer(n) and n > 0 do
    <<first, _::binary>> = bytes = :binary.encode_unsigned(n)
    (byte_size(bytes) - 1) * 8 + bit_length_byte(first)
  end

  defp bit_length(_), do: 0

  defp bit_length_byte(0), do: 0
  defp bit_length_byte(b), do: 1 + bit_length_byte(Bitwise.bsr(b, 1))

  defimpl Inspect do
    def inspect(cert, _opts) do
      "#Sinetex.Certificate<serial: #{cert.serial_field}, pc: #{cert.pc}, subject: #{inspect(cert.subject)}>"
    end
  end
end
