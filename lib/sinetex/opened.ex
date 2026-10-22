defmodule Sinetex.Opened do
  @moduledoc """
  The result of `Sinetex.open/2`.

    * `:content` - the content: decrypted, with its signature verified and,
      for C04 8 and 10, decompressed.
    * `:header` - the decoded `Sinetex.Header`. A `c03` other than `0x00`
      means the counterparty is reporting an error (§5.5.5): do not answer
      it with another error.
    * `:sender` - the `Sinetex.Certificate` that signed the content, or `nil`
      for clear text.
    * `:protection` - `:signed_and_encrypted`, `:signed` (C04 2, 3, 6 and 10)
      or `:clear` (the empty header of §5.6.3, only with `allow_clear: true`).
    * `:compression` - `:gzip` or `:zip` when the content was decompressed,
      `:none` otherwise. With C04 8 or 10, `:none` means the content did not
      start with GZIP or ZIP magic bytes and was returned as is.

  `inspect/2` leaves the content out.
  """

  @derive {Inspect, except: [:content]}
  @enforce_keys [:content, :header, :sender, :protection, :compression]
  defstruct [:content, :header, :sender, :protection, :compression]

  @type t :: %__MODULE__{
          content: binary(),
          header: Sinetex.Header.t(),
          sender: Sinetex.Certificate.t() | nil,
          protection: :signed_and_encrypted | :signed | :clear,
          compression: :gzip | :zip | :none
        }
end
