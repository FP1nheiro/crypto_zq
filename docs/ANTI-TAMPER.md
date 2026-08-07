# CZQ — Anti-tamper, o teto client-side, e recomendações

Este doc registra, sem rodeios, **até onde a proteção client-side vai** e **o que
realmente sobe o custo**. Baseado em ataques de red-team reais contra este client
(inclusive um patch de binário bem-sucedido).

## O teorema (por que não existe muro client-side)

O atacante é o **destinatário**. O client precisa desenhar o sprite e rodar o Lua,
então em algum instante o conteúdo existe em claro na RAM, e a rotina de decrypt +
a chave vivem no processo. Criptografia local **não guarda segredo de quem tem o
client** — só eleva o custo. É o mesmo motivo pelo qual todo DRM de software cai.

## O ataque que funcionou (documentado, para calibrar)

Um red-teamer dumpou o conteúdo assim, em resumo:

1. Descobriu que o `readFileContents` do client **decifra** qualquer arquivo quando
   chamado com o argumento `safe = 0` (o binding Lua fixa `1` = cru). É um **oráculo
   de decrypt** pronto.
2. Injetou um mod Lua não-sandboxed em `/mods/bot/` que usa **LuaJIT ffi** pra chamar
   essa função direto no endereço (`base+0x2DF1A0`), passando o contexto de proteção
   vivo, lendo o `std::string` de volta e gravando via `CreateFile/WriteFile`.
3. Quando as proteções armaram: **NOP no `jne`** do allowlist (1 instrução) e
   **encheu de espaço o bootstrap Lua anti-ffi** (era uma string em `.rdata`) — tudo
   numa cópia do exe. Bateu no `__fastfail` do decrypt (uma checagem parcial já ali).

**Lição:** cada proteção client-side é **1–2 instruções que ele dá NOP**. Contra um
patcher de binário, nenhuma checagem isolada segura. As camadas abaixo servem contra
o atacante **script-only** (roda Lua, não patcheia o exe) — não contra o patcher.

## O que já está no client (contra script-only)

- **Sandbox de FFI em C** (não como string Lua — uma string de bootstrap é trivial de
  achar e blanquear). Limpa `ffi` de `package.preload`/`loaded`/global e remove
  `package.loadlib` (que reabre `luaopen_ffi` direto). Nenhum módulo legítimo usa ffi.
- **Allowlist do manifest**: `.lua`/`.otmod`/`.otui` fora do manifest assinado são
  recusados (silenciosamente — sem string reveladora). `/bot/` **não** é mais isento.
- **Binding seguro**: `g_resources.readFileContents` do Lua é o `safe` (cru) → devolve
  ciphertext, não plaintext.

Tudo isso cai com um NOP se o exe for patchado. É degrau, não muro.

## O que REALMENTE para o patcher (as únicas 3 coisas)

Em ordem de esforço/retorno:

### 1. Amarrar a chave à integridade do binário (`.text` hash) — client-only, DIY
A chave deriva **também do hash da seção `.text`**. Patchou o `jne` do allowlist →
a `.text` muda → a chave sai errada → a decrypt devolve **lixo**. Faz o patch quebrar
a própria decrypt.
- **Circularidade resolvida:** as shares moram no `.rdata` (não na `.text`), então
  hashear só a `.text` é independente delas. Fluxo: compila o client → hasheia a
  `.text` → resolve as shares pra `reconstruct(shares) XOR H(.text) = master` →
  aplica as shares no `.rdata` (passo pós-build de PE-patch).
- **Limite:** um atacante pode patchar a função de hash pra retornar o hash original
  (constante). Sobe de "NOP em 1 instrução" pra "reverter e derrotar a checagem" —
  degrau grande, não muro. Mais forte se a checagem for virtualizada.

### 2. VMProtect (Ultimate) — a versão limpa do item 1 + virtualização
- `VMProtectIsValidImageCRC()` faz o item 1 pronto (patchou → o client morre).
- **Virtualiza** `czq_boot` + os hooks de decrypt → o atacante não acha mais o
  endereço da função pra chamar por FFI, nem o `jne` pra NOPar. Mata o método linear
  (disassembly + panic strings) que o red-team usou — "semanas, não horas".
- É o **plano** (ver `HARDENING_VMPROTECT.md` no client). É a resposta direta ao
  ataque acima. Rodar por último no pipeline (RFC §17).

### 3. Segredo do servidor no login — o único que muda a NATUREZA
A decrypt não fecha sem o segredo entregue no login autenticado
(`master_sprites = HKDF(sprite_secret, segredo_do_servidor)`). Aí nem chamar a função
direto por FFI adianta: **sem credencial, sai lixo**. O terreno já está pronto — a key
de sprites já é um tronco independente (`context.rs`). Contradiz o RFC D3 (sem key
server) — é decisão de produto, adição modesta no TFS, não redesenho.

## Higiene de strings (o que o `strings` entrega)

Um `strings` no exe não deve revelar a arquitetura:
- **Strings descritivas** (logs/erros do tipo "assinatura OK, master' reconstruido,
  allowlist…") — **removidas** (mapeavam o desenho de graça). Erros de bloqueio agora
  são silenciosos (o loader stock mostra "cannot read", que não é tell).
- **Nomes de artefato** (`manifest.czq`, `spr_chunk_`, `.czq`) — ver as duas defesas:
  1. **Renomear pra nomes inócuos** (`client.dat`, `sN.bin`, sem `.czq`) — some do
     binário **e** do disco (parece client normal). É o recomendado.
  2. **Ofuscar os literais** (XOR, decodifica em runtime) — some do `strings`, mas os
     arquivos no disco continuam com o nome antigo (meia solução).
- **Paths/nomes de módulo/versões de crate do Rust** — já removidos com
  `--remap-path-prefix` + nightly `-Zlocation-detail=none` (ver `HARDENING.md`).
- O catch-all definitivo é o **String Encryption do VMProtect**.

## Resumo executivo

- A cifra está correta; **a fronteira de confiança (o client) é o problema.**
- Camadas client-side (sandbox, allowlist) param o **script-only**, não o **patcher**.
- Para o patcher, só valem: **(1) chave amarrada à `.text`**, **(2) VMProtect
  (image-CRC + virtualização)**, **(3) segredo no servidor**. As duas primeiras são
  client-only; a terceira muda a natureza.
- Para arte como ativo crítico, o caminho continua sendo **watermark por conta**
  (atribuição > prevenção) — cifra local não impede cópia de quem tem o client.
