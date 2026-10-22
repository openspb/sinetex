defmodule Sinetex.Error do
  @moduledoc """
  A protocol error, as defined by the security error table of the
  *Manual de Segurança do SFN* (§5.5.1).

  Fields:

    * `:c03` - the error code that goes in field C03 of the header
      (`0x01`..`0x14`, or `0xFF`).
    * `:egen` - the matching GEN0004 error code (`"EGEN9901"`..`"EGEN9920"`),
      or `nil` for `0xFF`.
    * `:field` - the header field the error refers to (`:c01`..`:c15`,
      `:body`), or `nil`.
    * `:message` - a short description, in English.
    * `:reason` - the internal cause, **for logs only**. It may say more than
      `:c03` does (see the `c14_errors: :uniform` option of `Sinetex.open/2`),
      so do not send it to the counterparty.

  The struct is an exception, so it can be raised, but `Sinetex` functions
  always return it in an `{:error, error}` tuple.
  """

  @table %{
    0x01 => {"EGEN9901", :c01, "header size is zero or incompatible"},
    0x02 => {"EGEN9902", :c02, "invalid or incompatible protocol version"},
    0x03 =>
      {"EGEN9903", :c06, "invalid recipient key algorithm, or it does not match the certificate"},
    0x04 => {"EGEN9904", :c07, "invalid symmetric key algorithm"},
    0x05 =>
      {"EGEN9905", :c08, "invalid sender key algorithm, or it does not match the certificate"},
    0x06 => {"EGEN9906", :c09, "invalid hash algorithm, or it does not match"},
    0x07 => {"EGEN9907", :c10, "invalid certification authority of the recipient certificate"},
    0x08 => {"EGEN9908", :c11, "invalid serial number of the recipient certificate"},
    0x09 => {"EGEN9909", :c12, "invalid certification authority of the sender certificate"},
    0x0A => {"EGEN9910", :c13, "invalid serial number of the sender certificate"},
    0x0B => {"EGEN9911", :c15, "invalid signature"},
    0x0C => {"EGEN9912", :c13, "the certificate does not belong to the sender of the message"},
    0x0D => {"EGEN9913", :c14, "could not extract the symmetric key"},
    0x0E => {"EGEN9914", :c14, "error in the symmetric algorithm"},
    0x0F => {"EGEN9915", :body, "body size is not a multiple of 8"},
    0x10 => {"EGEN9916", :c13, "certificate not activated"},
    0x11 => {"EGEN9917", :c13, "certificate expired or revoked"},
    0x12 => {"EGEN9918", nil, "generic security layer error"},
    0x13 => {"EGEN9919", :c04, "invalid or incompatible special treatment indicator"},
    0x14 => {"EGEN9920", :c13, "invalid certificate"},
    0xFF => {nil, nil, "error outside the security scope"}
  }

  @codes @table |> Map.keys() |> Enum.sort()

  @typedoc "A C03 error code: `0x01`..`0x14` or `0xFF`."
  @type code :: 0x01..0x14 | 0xFF

  @type field ::
          :c01
          | :c02
          | :c04
          | :c06
          | :c07
          | :c08
          | :c09
          | :c10
          | :c11
          | :c12
          | :c13
          | :c14
          | :c15
          | :body
          | nil

  @type t :: %__MODULE__{
          c03: code(),
          egen: String.t() | nil,
          field: field(),
          message: String.t(),
          reason: term()
        }

  defexception [:c03, :egen, :field, :message, :reason]

  @doc """
  Builds the error for `code`, keeping `reason` for logs.

      iex> error = Sinetex.Error.new(0x0B)
      iex> {error.egen, error.field, error.message}
      {"EGEN9911", :c15, "invalid signature"}
  """
  @spec new(code(), term()) :: t()
  def new(code, reason \\ nil) do
    case Map.fetch(@table, code) do
      {:ok, {egen, field, message}} ->
        %__MODULE__{c03: code, egen: egen, field: field, message: message, reason: reason}

      :error ->
        raise ArgumentError, "unknown C03 error code: #{inspect(code)}"
    end
  end

  @doc """
  All valid C03 error codes, in ascending order.
  """
  @spec codes() :: [code(), ...]
  def codes, do: @codes

  @doc """
  Returns `true` if `code` is a valid, non-zero C03 error code.
  """
  @spec code?(term()) :: boolean()
  def code?(code), do: Map.has_key?(@table, code)

  @impl true
  def message(%__MODULE__{c03: c03, egen: egen, message: message}) do
    prefix = if egen, do: "#{egen} (C03 0x#{hex(c03)})", else: "C03 0x#{hex(c03)}"
    "#{prefix}: #{message}"
  end

  defp hex(code), do: code |> Integer.to_string(16) |> String.pad_leading(2, "0")

  defimpl Inspect do
    # The reason may hold a list of codes, such as `[8, 10]`, which would
    # otherwise print as a charlist.
    def inspect(error, opts), do: Inspect.Any.inspect(error, %{opts | charlists: :as_lists})
  end
end
