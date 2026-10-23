# Sinetex

O envelope de segurança da **RSFN** (Rede do Sistema Financeiro Nacional), a
rede que liga instituições financeiras, câmaras e o Banco Central do Brasil,
para Elixir.

A biblioteca monta e abre o cabeçalho de segurança de 588 bytes definido no
capítulo 5 do [*Manual de Segurança do SFN*][manual], que é público (Vol. I,
versão 6.00; o capítulo 5 é igual ao da versão 5.07). Cobre o **Protocolo de
Segurança v3** (AES-256-GCM) e o **v2** (3DES, legado): assinatura, cifra,
compactação e a tabela de erros do C03. Versões novas do manual saem na página
[Comunicação Eletrônica de Dados](https://www.bcb.gov.br/estabilidadefinanceira/comunicacaodados)
do Banco Central.

[Read in English](README.md).

O [guia em português](guides/manual.md) põe cada função ao lado da seção do
manual que ela implementa.

## Escopo

**Dentro:** o cabeçalho (C01–C15), emissão e recepção em v2 e v3, todos os
valores de C04, a tabela de erros com a regra do menor código, GZIP e ZIP.

**Fora:** transporte (MQ, Connect:Direct, SFTP), o XML das mensagens,
habilitação e ativação de certificados, LCR, armazenamento de chaves. A
biblioteca trabalha com bytes: você entrega o conteúdo e as chaves e recebe o
envelope, e vice-versa. Não tem dependências em tempo de execução além de
`:crypto` e `:public_key`.

## Instalação

```elixir
def deps do
  [{:sinetex, "~> 0.2"}]
end
```

Elixir 1.16 ou mais novo, OTP 26 ou mais novo. A versão 2 do protocolo precisa
de 3DES no OpenSSL ao qual o OTP está ligado.

## Uso

### Chaves e certificados

```elixir
# Seu certificado e sua chave privada (PEM ou DER; PKCS#1, PKCS#8 ou PKCS#8 cifrado)
{:ok, me} = Sinetex.Identity.load(File.read!("me.crt"), File.read!("me.key"))

# O certificado da contraparte
{:ok, peer} = Sinetex.Certificate.load(File.read!("peer.crt"))
```

C10 e C12 levam o código da AC (PC). Ele é lido de `OU=CSPB-n` no emissor do
certificado. Para certificados sem esse campo, informe o código:
`Sinetex.Certificate.load(pem, pc: 4)`.

Os certificados precisam ser RSA-2048, com número de série de até 16 bytes,
como o cabeçalho exige. Para um número de série maior, ou uma contraparte que
identifica o certificado por outro número, informe o número que vai no C11/C13:
`Sinetex.Certificate.load(pem, serial: 0x3B3BC056)` (a mesma opção existe em
`Sinetex.Identity.load/3`). Os dois lados precisam usar o mesmo valor.

Um arquivo PKCS#12 (`.pfx`, `.p12`) é lido depois de convertido para PEM:

```
openssl pkcs12 -in me.pfx -clcerts -nokeys -out me.crt
openssl pkcs12 -in me.pfx -nocerts -out me.key
```

O segundo comando pede uma senha nova e mantém a chave cifrada; passe-a com
`Sinetex.Identity.load(cert, key, password: "...")`. No OpenSSL 3, arquivos
mais antigos (RC2-40) precisam de `-legacy` nos dois comandos.

### Emissão

```elixir
{:ok, envelope} = Sinetex.seal(xml, from: me, to: peer)

# Arquivo compactado (C04 8). O formato é obrigatório: veja abaixo.
{:ok, envelope} = Sinetex.seal(arquivo, from: me, to: peer, c04: 8, compression: :gzip)

# Versão 2
{:ok, envelope} = Sinetex.seal(xml, from: me, to: peer, version: 2)
```

### Recepção

```elixir
case Sinetex.open(envelope, as: me, from: peer) do
  {:ok, %Sinetex.Opened{content: content, header: header}} ->
    # header.c03 != 0 quer dizer que a contraparte está reportando um erro
    ...

  {:error, %Sinetex.Error{c03: c03, egen: egen} = error} ->
    # c03 é o código da tabela do manual; egen, o código da GEN0004 (EGEN99xx)
    Logger.warning(Exception.message(error))
end
```

`:from` aceita uma lista de certificados, para um remetente que está trocando
de certificado. Outras opções:

| Opção | Padrão | |
|---|---|---|
| `:known` | `[]` | Outros certificados. Mensagem assinada com um deles falha com `0x0C` (certificado não é do emissor) em vez de `0x0A` |
| `:certificate_check` | nenhum | `fn cert, header -> :ok \| {:error, c03} end`, para o que depende do seu cadastro de certificados: não ativado (`0x10`), vencido ou revogado (`0x11`), inválido (`0x14`) |
| `:c14_errors` | `:manual` | `:uniform` reporta a falha ao decifrar o C14 como `0x0E` em vez de `0x0D`. Veja o [SECURITY.md](SECURITY.md) |
| `:trim_padding` | `false` | A v2 mantém o padding `0x00`, como manda o manual. `true` remove até 7 zeros finais |
| `:allow_clear` | `false` | Aceita o cabeçalho "vazio" (todos os campos zerados, como no eco da GEN0001), cujo corpo não é assinado nem cifrado |
| `:pc_check` | `:strict` | `:ignore` não confere o C10 (`0x07`) e escolhe o remetente só pelo C13, para contrapartes que não preenchem C10/C12 com os PCs dos certificados. A assinatura é verificada do mesmo jeito |
| `:max_output_bytes` | 512 MiB | Teto do conteúdo descompactado |
| `:max_input_bytes` | `:infinity` | Teto do envelope |

### Reportar um erro

A biblioteca nunca responde a ninguém. Quando `open/2` falha, você decide se
devolve uma GEN0004. `error_envelope/2` monta o envelope dela: assinado, sem
cifra (C04 3), com o C03 preenchido. O XML da GEN0004 fica com você.

```elixir
with {:error, %Sinetex.Error{} = error} <- Sinetex.open(envelope, as: me, from: peer) do
  Sinetex.error_envelope(gen0004_xml(error.egen), from: me, to: peer, c03: error.c03)
end
```

### Compactação

Com C04 8 e 10, `:compression` é obrigatório na emissão. Não há padrão porque o
formato certo depende do destino: as câmaras usam GZIP; o manual e os
servidores SFTP do Bacen usam ZIP com DEFLATE.

Na recepção, o formato é detectado pelos magic bytes, não pelo C04, e
`%Sinetex.Opened{compression: :gzip | :zip | :none}` diz qual foi encontrado.
Conteúdo marcado como compactado que não é GZIP nem ZIP é devolvido como
chegou, o que já foi observado na prática.

`compression_level: :best_speed` (ou `:none`, `:best_compression`, `0..9`)
troca tamanho por velocidade na emissão. A saída padrão não muda.

### Memória

`seal/2` e `open/2` trabalham com binários inteiros: o conteúdo, o envelope e
os resultados intermediários ficam na memória ao mesmo tempo, então o pico é
algumas vezes o tamanho do conteúdo.

## Inspecionar tráfego real

`tools/header_dump.exs` imprime o cabeçalho de um envelope sem decifrar nada e
sem chaves. Não depende da biblioteca:

```
elixir tools/header_dump.exs envelope.bin
```

## Documentação

* Documentação da API: [HexDocs](https://hexdocs.pm/sinetex).
* [docs/SPEC.md](docs/SPEC.md) (inglês): o que a biblioteca faz com cada
  byte, com a origem de cada regra (manual, prática de mercado ou decisão da
  biblioteca).
* [guides/manual.md](guides/manual.md): cada função ao lado da seção do manual.
* [SECURITY.md](SECURITY.md) (inglês): notas de segurança e como reportar uma vulnerabilidade.

## Desenvolvimento

```
mix test
```

Os certificados e chaves de teste são gerados por
`test/support/gen_fixtures.sh` (precisa do `openssl`) na primeira execução.
Nenhuma chave ou amostra de terceiros está no repositório.

Os testes de interoperabilidade rodam contra uma implementação independente em
Python, escrita só a partir da especificação. Eles precisam do Python 3 com o
pacote `cryptography` e são pulados sem ele:

```
python3 -m venv .venv && .venv/bin/pip install cryptography
SINETEX_PYTHON=.venv/bin/python mix test
```

## Licença

Apache-2.0: veja os arquivos `LICENSE` e `NOTICE`.

[manual]: https://www.bcb.gov.br/content/estabilidadefinanceira/cedsfn/Manual%20de%20Seguran%C3%A7a%20do%20SFN%20-%20Vol.I%20-%20v6_00.pdf
