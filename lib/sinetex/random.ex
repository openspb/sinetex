defmodule Sinetex.Random do
  @moduledoc false

  # Source of keys and nonces. Always :crypto.strong_rand_bytes/1, except when
  # the library itself is compiled for its own test suite: then a test may
  # install a deterministic generator in the process dictionary to produce
  # known-answer vectors. The hook does not exist in any other build, so it
  # cannot be switched on by configuration.

  if Code.ensure_loaded?(Mix) and Mix.env() == :test do
    @spec bytes(non_neg_integer()) :: binary()
    def bytes(n) do
      case Process.get(:sinetex_test_rng) do
        nil -> :crypto.strong_rand_bytes(n)
        fun when is_function(fun, 1) -> fun.(n)
      end
    end
  else
    @spec bytes(non_neg_integer()) :: binary()
    def bytes(n), do: :crypto.strong_rand_bytes(n)
  end
end
