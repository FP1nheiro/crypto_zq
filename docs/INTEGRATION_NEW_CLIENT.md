# CZQ — Integração completa num client OTClientV8 novo (do zero)

Guia + diff de **tudo** que precisa entrar num client limpo (ex.:
`otclientv8-master`) para rodar a crypto CZQ. Acompanha o patch
[`CZQ_NEW_CLIENT.patch`](CZQ_NEW_CLIENT.patch) (edições dos arquivos stock portáveis).

Tudo fica **atrás de `WITH_CZQ`**: com a flag off, o build é idêntico ao stock.
Contexto de segurança e o teto honesto: ver `docs/ANTI-TAMPER.md` e `docs/HARDENING.md`
no repo do crypto.

---

## 0. Pré-requisito: compilar o núcleo (`czq_core.lib`)

O crypto vive **uma vez** em Rust (`crypto-core`) e o client linka como staticlib
(C ABI). Vendorize a pasta `crypto/` (crypto-core + packer) no client e compile:

```bash
cd crypto
cargo build --release -p crypto-core     # -> crypto/target/release/czq_core.lib (CRT dinamico=msvcrt)
cargo build --release -p packer          # -> crypto/target/release/czq-pack.exe (luajit embutido)
```

> **Endurecido:** para o build de release do `.lib`, use nightly p/ remover paths/
> nomes de módulo do binário: `cargo clean` e depois
> `$env:RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none"; cargo +nightly build --release -p crypto-core`
> (o `.cargo/config.toml` já remapeia o path pessoal). Ver `docs/HARDENING.md`.

O `crypto/` tem seu próprio `.cargo/config.toml` (remap de paths). Não commite a
`czq_build_material.h` gerada (carrega as shares secretas).

---

## 1. Arquivos NOVOS (copiar verbatim)

Copie do `v8_pxg` (referência) para o client novo, mesmos caminhos:

| Arquivo | Papel |
|---|---|
| `src/framework/core/czq/czq_core.h` | C ABI do núcleo (declarações) |
| `src/framework/core/czq/czqclient.{h,cpp}` | adapter fino `g_czq`: boot, decrypt cold/sprite, allowlist, nomes ofuscados |
| `src/framework/core/czq/czq_build_material.h` | **placeholder** (zeros); o packer gera o real, você copia por cima |
| `vc17/czq.props` | wiring MSVC (compila o adapter, linka `czq_core.lib`), gated em `WITH_CZQ=1` |

`czqclient.cpp` é o **único** arquivo que conhece client + CZQ (RFC §5.2). Ele já traz:
boot lazy, `decryptAsset` (cold/UI/.dat/lua), `decryptSprite` (chunks + LRU),
`knowsAsset`/`enforce*` (allowlist), e os **nomes de artefato ofuscados por XOR**
(`client.dat`/`sN.bin`/`.bin`) — nada de `manifest.czq`/`.czq` no binário.

---

## 2. Edições nos arquivos STOCK

### 2a. Portáveis — aplique o patch
O patch `CZQ_NEW_CLIENT.patch` é **CZQ puro** (sem ruído de fork) e cobre os **5
arquivos stock** editados: `resourcemanager.cpp`, `luainterface.cpp`,
`spritemanager.{h,cpp}` e `vc17/otclient.vcxproj`. Aplica limpo num OTClientV8 stock —
**verificado neste `otclientv8-master`, que já está integrado** (o patch foi aplicado):

```bash
cd otclientv8-master
patch -p1 < CZQ_NEW_CLIENT.patch      # ou: git apply CZQ_NEW_CLIENT.patch
```

> `settings.props` **não** é tocado — o import do `czq.props` fica no `vcxproj`.

O que o patch faz, resumido:
- **`resourcemanager.cpp`** (hook central, RFC §5.1):
  - em `readFileContents`: boot lazy do CZQ + `g_czq.decryptAsset(fullPath, buffer)`
    (decrypt transparente de cold/UI/.dat/lua); e **allowlist** — `.lua/.otmod/.otui`
    fora do manifest assinado são **recusados** (`czqBlockedAsset` → refuse silencioso,
    sem string reveladora). `/bot/` **não** é isento; `/downloads` é (updater HTTP).
  - em `fileExists`: reporta `.spr` presente quando o índice CZQ carregou; recusa
    kinds fora do manifest.
- **`luainterface.cpp`** (`createLuaState`): **sandbox de FFI em C** — remove `ffi` de
  `package.preload`/`loaded`/global e mata `package.loadlib`. Feito em C (não como
  string Lua) porque um bootstrap Lua em `.rdata` é trivial de blanquear.
- **`spritemanager.{h,cpp}`**: caminho de sprite **on-demand** (flag `m_czq`, boot no
  `loadSpr`, ramo de decode no `getSpriteImageCasual`) — ver 2b.
- **`vc17/otclient.vcxproj`**: `WITH_CZQ` default=1 no `<PropertyGroup Label="Globals">`
  + `<Import Project="czq.props"/>` por ÚLTIMO (para o `AdditionalDependencies` apended
  depois do `release.props`).

### 2b. Sprites — on-demand (o ponto crítico, já no patch)

> ⚠️ **SPRITES SÃO SOB DEMANDA — nunca preload.** Cada sprite é decifrado **na hora
> em que o renderer pede** `getSpriteImage(id)`. O `g_czq.decryptSprite(id, blob)` lê
> o **chunk dono** on-demand via `std::ifstream` (thread-safe, nunca PHYSFS fora da
> main thread), verifica o MAC **uma vez por chunk**, e mantém um **cache LRU limitado
> por bytes** (`kChunkCacheBudget` = 48 MB no `czqclient.h`) que despeja chunks antigos.
> **NUNCA** adicione um loop que decifra/carrega todos os sprites no boot — a `.spr`
> real tem ~180k–1M sprites e isso estoura a RAM.

O patch já traz a integração **adaptada à estrutura deste client** (`getSpriteImageCasual`,
sem enum `SprFormat`): um `bool m_czq`, o boot no `loadSpr` (marca `m_czq` +
`m_spritesCount = g_czq.spriteCount()` e retorna) e o ramo que decifra **um sprite por
vez** no `getSpriteImageCasual` — o **mesmo decoder RLE** do `.spr` clássico, lendo do
blob que o `g_czq.decryptSprite(id)` devolve.

**Adaptando a OUTRO client** (estrutura de sprite diferente): reproduza o padrão —
(1) no `loadSpr`, boota o CZQ e, se `spriteReady()`, marca o modo, seta
`m_spritesCount = g_czq.spriteCount()` e retorna `true`; (2) na função que decodifica um
sprite pra `Image`, ANTES de ler o `.spr`, chama `g_czq.decryptSprite(id, blob)` e
decodifica o blob (`[3 color-key][u16 size][RLE]`) com o seu decoder. ⚠️ Se o client
tiver HD/upscale, **não** force `m_spriteSize` a 32 com upscale ligado (gera imagem
64x64 blitada como 32x32 → heap corruption).

`fileExists` (no patch) já reporta o `.spr` como presente quando o índice CZQ carregou,
então o gate "Missing file" do stock não falha.

---

## 3. Gerar e instalar o material embutido + assets

1. **Empacote o client** (GUI `czq-pack-gui.exe` ou CLI):
   ```
   set CZQ_PASSPHRASE=sua-chave-secreta
   czq-pack packdir --in <client> --out <saida> --versions versions.xml --lua-compile
   ```
   Saída: `client.dat` (manifest cifrado, RENOMEADO), `data/.../chunks/sN.bin` +
   `index.bin`, cold assets cifrados no path espelhado, e `embed/czq_build_material.h`
   (as shares **secretas** deste build).
2. **Instale a chave**: copie `saida/embed/czq_build_material.h` por cima do placeholder
   em `src/framework/core/czq/czq_build_material.h`.
3. **Instale os assets**: copie `saida/data/...` sobre o `data/` do client e o
   `client.dat` na raiz montada (mesmo lugar do `init.lua`).

> **Rotação (RFC §16):** cada `packdir` gera chaves/permutação/cipher novos → o dump
> do build antigo morre. Vazou? novo pack + recompila + distribui pelo updater.

---

## 4. Compilar o client

```
msbuild vc17\otclient.sln -p:Configuration=DirectX -p:Platform=x64 -p:WITH_CZQ=1 -m
```
Sem `-p:WITH_CZQ=1` (ou `=0`) → build stock, CZQ ausente.

**CRT:** o `settings.props` compila `/MT` mas linka `msvcrt` (CRT dinâmico). O
`czq_core.lib` deve ser o build **sem** `+crt-static` (default do cargo). Se um dia
mudarem pra CRT estático de verdade: `RUSTFLAGS="-C target-feature=+crt-static"`.

---

## 5. Verificar (comportamento, sem strings reveladoras)

Não há mais log de atestação (era um tell). Verifique por comportamento:
- **Boot + jogo**: sprites, `.dat`, imagens e `.lua` (bytecode) renderizam normal.
- **Módulos carregam** (menu/login/in-game). Se um `.otmod`/`.lua`/`.otui` legítimo seu
  ficou **fora** do pack, ele é recusado (é o allowlist) — empacote aquele caminho.
- **Injeção bloqueada**: jogue um `.lua`/`.otmod`/`.otui` cru em qualquer lugar (incl.
  `/bot/`) → não roda (o loader mostra "cannot read"/"Missing file" stock).
- **FFI**: um módulo com `require("ffi")` recebe erro de módulo inexistente.
- **`strings` no exe**: não deve aparecer `manifest.czq`/`spr_chunk_`/`.czq` nem textos
  descritivos da arquitetura.

---

## 6. Recapitulação do que é copiado/editado

**Novos:** `src/framework/core/czq/{czq_core.h, czqclient.h, czqclient.cpp,
czq_build_material.h}`, `vc17/czq.props`, a pasta `crypto/` (+ `czq_core.lib` buildado).

**Editados (patch/adaptação):** `src/framework/core/resourcemanager.cpp`,
`src/framework/luaengine/luainterface.cpp`, `src/client/spritemanager.{h,cpp}`,
`vc17/settings.props`, `vc17/otclient.vcxproj`.

**Endurecimento já embutido nesta rev.:** manifest cifrado; índice de sprite denso sem
oráculos; remap de opcodes LuaJIT (+ Fase 1 opcional); duas keys (arquivos X / sprites
Y independentes); rotação de cipher por build; constantes de KDF em bytes crus; paths
do Rust removidos (nightly); allowlist `.lua/.otmod/.otui`; sandbox de FFI em C; nomes
de artefato inócuos + ofuscados. **Ainda por fazer (o que para o patcher):** amarrar a
chave ao hash da `.text`, VMProtect (image-CRC + virtualização), ou segredo no login —
ver `docs/ANTI-TAMPER.md`.
```
