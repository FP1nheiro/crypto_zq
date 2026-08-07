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
`resourcemanager.cpp`, `luainterface.cpp`, `vc17/settings.props` têm estrutura igual
à do stock. O patch os leva ao estado CZQ:

```bash
cd otclientv8-master
git apply --reject CZQ_NEW_CLIENT.patch      # ou: patch -p1 < CZQ_NEW_CLIENT.patch
```

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
- **`vc17/settings.props`**: `<Import Project="czq.props" .../>` (no-op sem `WITH_CZQ=1`).

### 2b. `vc17/otclient.vcxproj`
Adicione (o resto do diff desse arquivo é config PxG, ignore):
```xml
  <!-- dentro do <PropertyGroup Label="Globals">: liga CZQ por padrão na IDE -->
  <WITH_CZQ Condition="'$(WITH_CZQ)'==''">1</WITH_CZQ>
```
```xml
  <!-- ANTES de </Project>, DEPOIS do import de release.props: importado por ULTIMO
       para o AdditionalDependencies do czq.props apended sem %(...) -->
  <Import Project="czq.props" Condition="exists('czq.props')" />
```

### 2c. `spritemanager` — adaptar (estrutura varia por client)

> ⚠️ **SPRITES SÃO SOB DEMANDA — nunca preload.** Cada sprite é decifrado **na hora
> em que o renderer pede** `getSpriteImage(id)`. O `g_czq.decryptSprite(id, blob)` lê
> o **chunk dono** on-demand via `std::ifstream` (thread-safe, nunca PHYSFS fora da
> main thread), verifica o MAC **uma vez por chunk**, e mantém um **cache LRU limitado
> por bytes** (`kChunkCacheBudget` = 48 MB no `czqclient.h`) que despeja os chunks
> antigos. **NÃO** adicione um loop que decifra/carrega todos os sprites no boot —
> isso estoura a RAM (a `.spr` real tem ~180k–1M sprites). O ramo CZQ abaixo entra
> exatamente no ponto lazy `getSpriteImage(id)` do seu client, um sprite por vez.

O caminho de sprite depende da sua `spritemanager`. Padrão (referência: `v8_pxg`):

1. `spritemanager.h`: adicione o modo CZQ ao enum de formato (ou um `bool m_czq`):
   ```cpp
   enum class SprFormat { None, NormalSpr, OTV8EncryptedSpr, CzqChunks };
   ```
2. `spritemanager.cpp`, no `#include`s: `#include <framework/core/czq/czqclient.h>`.
3. Em `loadSpr(...)`: em vez de abrir o `.spr` em texto, **boota o CZQ** e, se houver
   índice, entra no modo chunks:
   ```cpp
   #ifdef WITH_CZQ
       g_czq.boot();
       if (g_czq.spriteReady()) {
           m_sprFormat = SprFormat::CzqChunks;
           m_spritesCount = (int)g_czq.spriteCount();
           m_spriteNativeSize = 32;   // sprite nativo 32x32
           // NAO force m_spriteSize aqui (reflete o fator de HD/upscale; forcar 32
           // com upscale ligado -> imagem 64x64 blitada como 32x32 -> heap corruption).
           m_loaded = true;
           return true;
       }
   #endif
   ```
4. Na função que **decodifica** um sprite pra `Image` (no v8_pxg é
   `decodeSpriteImageCasual`; no stock é `getSpriteImageCasual`/`getSpriteImageHd`),
   adicione o ramo CZQ ANTES da leitura do `.spr`:
   ```cpp
   #ifdef WITH_CZQ
       if (m_sprFormat == SprFormat::CzqChunks) {
           std::string blob;
           if (!g_czq.decryptSprite((uint32_t)id, blob) || blob.size() < 5)
               return nullptr;
           // 'blob' tem o MESMO layout [3 bytes color-key][u16 size][RLE] que o
           // decoder normal do .spr espera — decodifique-o igual ao ramo NormalSpr.
           // (Ver a implementacao completa em v8_pxg/src/client/spritemanager.cpp.)
       }
   #endif
   ```
   O `blob` é idêntico ao bloco de um sprite no `.spr` — reaproveite o decoder RLE que
   você já tem. Copie o corpo completo do ramo do `v8_pxg` como base.

`fileExists` (patch 2a) já reporta o `.spr` como presente quando o índice CZQ está
carregado, então o gate "Missing file" do stock não falha.

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
