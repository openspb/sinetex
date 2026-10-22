# Guia: o manual e a biblioteca

Este guia percorre o capítulo 5 do *Manual de Segurança do SFN* e mostra onde
cada regra está na biblioteca. A numeração das seções é a do Vol. I da versão
6.00, igual à da versão 5.07 no capítulo 5.

A especificação completa, com a origem de cada regra, está em
[docs/SPEC.md](../docs/SPEC.md) (em inglês). Lá, cada regra é marcada como
normativa (está no manual), prática de mercado (o manual é omisso; precisa ser
confirmada com tráfego real) ou decisão da biblioteca.

## Mapa das seções

| Seção do manual | Assunto | Na biblioteca |
|---|---|---|
| §5.1, Tabela 1, Anexo A | Campos C01–C15 do cabeçalho | `Sinetex.Header` |
| §5.1.4, §5.2.6 | Número de série em C11/C13 | `Sinetex.Serial`; campo `serial_field` de `Sinetex.Certificate` |
| §4.2.6 | `OU=CSPB-n` e o código da PC (C10/C12) | `Sinetex.Certificate.load/2`, opção `:pc` |
| §4.2.7, §4.2.8, §4.4.16 | RSA-2048, expoente diferente de 3 | `Sinetex.Certificate.load/2`, `Sinetex.Identity.load/3` |
| §5.1.2, §5.1.2.1, Anexo A | Versão 2: 3DES, paridade ímpar, IV | `Sinetex.seal/2` com `version: 2` |
| §5.1.3 a §5.1.3.4 | Versão 3: AES-256-GCM, chave e *nonce* no C14 | `Sinetex.seal/2` (padrão) |
| §5.1.7 | SHA-256 com chaves de 2048 bits | C09 = `0x03` |
| §5.2 (§5.2.3 a §5.2.9) | Emissão: compactar, completar, assinar, cifrar | `Sinetex.seal/2` |
| §5.2.8 | Chave simétrica nova a cada mensagem | `Sinetex.seal/2` |
| §5.3 (§5.3.2 a §5.3.6) | Recepção | `Sinetex.open/2` |
| §5.4 | Registro de auditoria | ainda não implementado |
| §5.5.1 | Tabela de erros (C03, EGEN99xx) | `Sinetex.Error` |
| §5.5.3 | Vários erros: vale o de menor código | `Sinetex.open/2` |
| §5.5.2, §5.5.4, §5.5.7 | GEN0004 só assinada, com o C03 | `Sinetex.error_envelope/2` |
| §5.5.5 | Não responder erro com erro | `header.c03` em `Sinetex.Opened` |
| §5.5.8 | Erro fora do escopo de segurança (`0xFF`) | `Sinetex.Error` |
| §5.6, §5.6.1, §5.6.2 | Tratamento especial (C04) | opção `:c04` de `Sinetex.seal/2` |
| §5.6.3 | Cabeçalho "vazio" (eco da GEN0001) | opção `allow_clear: true` de `Sinetex.open/2` |
| §5.7.13 | C04 6 e 10: uso público, sem cifra | opção `:c04` |
| §5.7.14 | O padding da v2 não é removido | opção `:trim_padding` de `Sinetex.open/2` |
| §5.8.27 | ZIP com DEFLATE nos servidores SFTP | `compression: :zip` |
| §4.4.10, §4.5.11, §4.5.12, §5.3.2 | Certificado ativo, revogado ou vencido | opção `:certificate_check` de `Sinetex.open/2` |

## Certificados e chaves (§4.2, §4.4.16, §5.1.4)

```elixir
{:ok, me} = Sinetex.Identity.load(File.read!("me.crt"), File.read!("me.key"))
{:ok, peer} = Sinetex.Certificate.load(File.read!("peer.crt"))
```

Na carga, a biblioteca confere o que o protocolo exige: chave RSA de
exatamente 2048 bits (o que garante o bit mais significativo do módulo
ligado), expoente público diferente de 3 e número de série de até 16 bytes,
que é o que cabe nos 32 caracteres de C11/C13. Para um número maior, ou quando
a contraparte conhece o certificado por outro número, a opção `serial:` define
o número que vai no C11/C13. Os dois lados precisam usar o mesmo valor.

O código da PC vem de `OU=CSPB-n` no emissor do certificado (§4.2.6). Um
certificado fora do padrão SPB, como os que algumas câmaras usam, não tem esse
campo: informe o código com `pc:`. Sem ele, a carga falha com
`{:error, :pc_code_required}`. A biblioteca não tenta adivinhar a AC pelo nome.

A chave privada pode vir em PEM ou DER, PKCS#1 ou PKCS#8, inclusive PKCS#8
cifrado (`password:`).

### Arquivo PKCS#12 (`.pfx`, `.p12`)

A biblioteca não lê PKCS#12 diretamente. Converta o arquivo para PEM:

```
openssl pkcs12 -in me.pfx -clcerts -nokeys -out me.crt
openssl pkcs12 -in me.pfx -nocerts -out me.key
```

O segundo comando pede uma senha nova e grava a chave cifrada, que é carregada
com `Sinetex.Identity.load(cert, key, password: "...")`. Evite gravar a chave
sem senha. No OpenSSL 3, arquivos mais antigos, cifrados com RC2-40, precisam
de `-legacy` nos dois comandos; os mais novos (PBES2 com AES-256) não.

## Emissão (§5.2)

`Sinetex.seal/2` segue a ordem do manual:

1. compacta, se o C04 for 8 ou 10;
2. completa com `0x00` até múltiplo de 8 (só na v2, §5.2.3);
3. assina o resultado com RSASSA-PKCS1-v1_5 e SHA-256 (C15);
4. cifra com uma chave nova (§5.2.8), se o C04 indicar cifra, e põe a chave
   cifrada com a chave pública do destinatário no C14;
5. preenche o cabeçalho.

```elixir
{:ok, envelope} = Sinetex.seal(xml, from: me, to: peer)
{:ok, envelope} = Sinetex.seal(arquivo, from: me, to: peer, c04: 8, compression: :gzip)
```

Sem cifra (C04 2, 3, 6 e 10), o destinatário é opcional; o C14 vai zerado.

## Recepção (§5.3) e erros (§5.5)

`Sinetex.open/2` trabalha em duas fases:

* **Fase A, cabeçalho.** Todas as checagens rodam e, se houver mais de um
  erro, vale o de menor código (§5.5.3).
* **Fase B, criptografia.** Decifra o C14, decifra o corpo, verifica a
  assinatura e descompacta, nessa ordem, parando no primeiro erro. Por isso
  um `0x0B` (assinatura) só aparece quando a decifragem deu certo, embora seu
  código seja menor que `0x0D` e `0x0E`.

```elixir
case Sinetex.open(envelope, as: me, from: peer) do
  {:ok, %Sinetex.Opened{content: content, header: header}} -> ...
  {:error, %Sinetex.Error{c03: c03, egen: egen, field: field}} -> ...
end
```

O erro traz o código do C03, o código da GEN0004 (`EGEN9901` a `EGEN9920`), o
campo do cabeçalho e uma mensagem. O motivo interno (campo `reason`) serve só
para log: não o mande para a contraparte.

Sem cifra (C04 2, 3, 6 e 10) não há chave simétrica: C06 não é conferido e o
C07 pode vir `0x00`, além do valor da versão.

Por padrão o C10 precisa ser o PC do seu certificado e o remetente é escolhido
pelo C13 e pelo C12. Com uma contraparte que não preenche C10/C12 com os PCs
dos certificados, `pc_check: :ignore` deixa de conferir o C10 e escolhe o
remetente só pelo C13; o C12 só desempata entre remetentes com o mesmo número
de série. A assinatura é verificada do mesmo jeito.

Os erros que dependem do seu cadastro de certificados (§4.4.10, §4.5.11,
§5.3.2) ficam com você, pela opção `:certificate_check`:

| C03 | EGEN | Quando |
|---|---|---|
| `0x10` | EGEN9916 | certificado não ativado |
| `0x11` | EGEN9917 | certificado vencido ou revogado |
| `0x14` | EGEN9920 | certificado inválido |

```elixir
check = fn cert, header ->
  cond do
    revogado?(cert) -> {:error, 0x11}
    not ativo?(cert) and header.c04 != 1 -> {:error, 0x10}
    true -> :ok
  end
end

Sinetex.open(envelope, as: me, from: peer, certificate_check: check)
```

O C04 1 indica que o remetente usa um certificado ainda não ativado (o caso da
GEN0006); o cabeçalho é passado para a função justamente para permitir isso.

Pela regra de §4.5.12, o certificado deixa de valer às 24h do dia anterior ao
"válido até". A biblioteca ainda não faz essa conta; use `cert.not_after`.

## Responder com GEN0004 (§5.5.2, §5.5.4, §5.5.5, §5.5.7)

A biblioteca nunca responde a ninguém. Para devolver um erro, monte o XML da
GEN0004 e chame `Sinetex.error_envelope/2`, que gera um envelope só assinado
(C04 3) com o C03 preenchido:

```elixir
with {:error, %Sinetex.Error{} = error} <- Sinetex.open(envelope, as: me, from: peer) do
  Sinetex.error_envelope(gen0004_xml(error.egen), from: me, to: peer, c03: error.c03)
end
```

Uma mensagem recebida com C03 diferente de zero é a contraparte reportando um
erro. Ela abre normalmente, o código fica em `opened.header.c03`, e não deve
ser respondida com outro erro (§5.5.5).

Antes de responder automaticamente às falhas de C14 (`0x0D`), leia o
[SECURITY.md](../SECURITY.md): esse código pode servir de oráculo para um
ataque à cifra RSA. A opção `c14_errors: :uniform` troca o `0x0D` por `0x0E`.

## Tratamento especial, C04 (§5.6)

| C04 | Uso | Compactado | Cifrado |
|---:|---|:-:|:-:|
| 0 | mensagem ou arquivo, assinado e cifrado (padrão) | | ✔ |
| 1 | certificado ainda não ativado (GEN0006) | | ✔ |
| 2 | *broadcast* público, sem destinatário | | |
| 3 | mensagem de segurança, como a GEN0004 | | |
| 4 | arquivo não compactado | | ✔ |
| 6 | arquivo não compactado, uso público (§5.7.13) | | |
| 8 | arquivo compactado | ✔ | ✔ |
| 10 | arquivo compactado, uso público (§5.7.13) | ✔ | |

Todos são assinados. O manual não diz com todas as letras que 1 e 4 são
cifrados: é o que se observa na prática.

O cabeçalho "vazio" de §5.6.3, com tudo zerado menos o C01, traz o corpo em
claro, sem assinatura. Por padrão ele é recusado com `0x02`; com
`allow_clear: true`, o conteúdo volta marcado `protection: :clear`. C11 e C13
podem vir com bytes `0x00` ou com o número de série zero no formato de §5.1.4
(32 caracteres `"0"`).

## Compactação (§5.6.2, §5.8.27)

O manual fala em ZIP; nos servidores SFTP do Bacen, ZIP com DEFLATE (§5.8.27).
As câmaras usam GZIP. Como o formato depende do destino, a emissão com C04 8
ou 10 exige `compression: :gzip` ou `compression: :zip`.

Na recepção, o formato é reconhecido pelos *magic bytes*, e
`opened.compression` diz qual foi encontrado. Conteúdo marcado como
compactado que não é GZIP nem ZIP volta como chegou.

Na emissão, `compression_level:` (`:best_speed`, `:best_compression`, `:none`
ou `0..9`) troca tamanho por velocidade. Sem a opção, a saída é a de sempre.

## Versão 2 (§5.1.2, §5.7.14)

A versão 2 usa 3DES e completa o conteúdo com `0x00` até múltiplo de 8. O
manual manda **não** remover esse padding (§5.7.14), e a biblioteca devolve o
conteúdo exatamente como foi assinado. Se o seu conteúdo não termina em zeros
legítimos, `trim_padding: true` remove até 7 zeros finais.

Prefira a versão 3 sempre que a contraparte aceitar. Num OpenSSL em modo FIPS,
o 3DES pode não estar disponível.

## Conferir com tráfego real

Alguns pontos seguem a prática de mercado porque o manual é omisso, como a
ordem dos bytes do C01 e o preenchimento do C14 quando não há cifra. A lista
está na seção 9 da [SPEC](../docs/SPEC.md). Para conferi-los num ambiente de
homologação, `tools/header_dump.exs` imprime o cabeçalho de um envelope sem
decifrar nada e sem precisar de chaves:

```
elixir tools/header_dump.exs envelope.bin
elixir tools/header_dump.exs --offset 64 registro.bin   # pula 64 bytes antes do cabeçalho
```
