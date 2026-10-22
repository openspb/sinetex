defmodule Sinetex.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/openspb/sinetex"

  def project do
    [
      app: :sinetex,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      dialyzer: [
        plt_add_apps: [:mix],
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        flags: [:error_handling, :extra_return, :missing_return, :underspecs]
      ]
    ]
  end

  def application do
    [extra_applications: [:crypto, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    "Security envelope of the Brazilian Financial System Network (RSFN/SPB, Bacen): " <>
      "588-byte header, Security Protocol v2 (3DES) and v3 (AES-256-GCM)."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md README.pt-BR.md LICENSE NOTICE CHANGELOG.md SECURITY.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: [
        "README.md",
        "README.pt-BR.md",
        "guides/manual.md",
        "docs/SPEC.md",
        "SECURITY.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        Guides: ["README.pt-BR.md", "guides/manual.md"],
        Specification: ["docs/SPEC.md", "SECURITY.md"]
      ],
      groups_for_modules: [
        API: [Sinetex, Sinetex.Identity, Sinetex.Certificate, Sinetex.Opened, Sinetex.Error],
        Format: [Sinetex.Header, Sinetex.Serial]
      ]
    ]
  end
end
