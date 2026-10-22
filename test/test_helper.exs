Sinetex.Fixtures.ensure_generated!()

# The interoperability tests need Python 3 with the `cryptography` package.
# SINETEX_PYTHON points to the interpreter (default: python3). Without it the
# tests are skipped, unless SINETEX_REQUIRE_INTEROP=1.
python = System.get_env("SINETEX_PYTHON", "python3")

python_exe =
  if String.contains?(python, "/") do
    if File.exists?(python), do: Path.expand(python)
  else
    System.find_executable(python)
  end

interop? =
  python_exe != nil and
    match?({_, 0}, System.cmd(python_exe, ["-c", "import cryptography"], stderr_to_stdout: true))

Application.put_env(:sinetex, :test_python, python_exe)

exclude =
  cond do
    interop? ->
      []

    # Set in CI, so that a broken Python setup fails instead of skipping.
    System.get_env("SINETEX_REQUIRE_INTEROP") in ["1", "true"] ->
      raise "SINETEX_REQUIRE_INTEROP is set, but #{python} with `cryptography` was not found"

    true ->
      IO.puts("Skipping interop tests: #{python} with the `cryptography` package not found.")
      [:interop]
  end

ExUnit.start(exclude: exclude)
