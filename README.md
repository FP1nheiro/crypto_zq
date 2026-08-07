# CZQ — Subsistema de Criptografia e Anti-Tamper do Client

Implementação da **RFC v1.0** (`rfc-cripto-client-v1.md`). Servidor TFS; clients
Mehah (opentibiabr) e OTClientV8 (cobre OTAV8). Raiz de confiança embutida no
client, derivação local, **sem key server**, resposta a incidente por **rotação de
build**.

> Calibração de expectativa (RFC §1): isto **não** é inquebrável. O alvo é elevar o
> custo de reversão a semanas de trabalho; a defesa estratégica é a rotação barata e
> frequente de build. Nenhum esquema client-side resiste a um dump de RAM
> perfeitamente sincronizado — mitigamos a janela (zeroize) e virtualizamos a raiz.

---

## Decisão de arquitetura: um único núcleo criptográfico

O ponto que a RFC marca como *load-bearing* (§6) é que **packer e client concordem
byte-a-byte**; se divergirem, a descriptografia falha. Em vez de manter duas
implementações e torcer para baterem, o crypto vive **uma vez** em Rust
(`crypto-core`) e é consumido pelos dois lados:

```
                    ┌──────────────────────────┐
                    │   crypto-core  (Rust)     │  envelope, cifras, KDFs, shares,
                    │   rlib + staticlib (C ABI)│  per-sprite, manifest/Ed25519
                    └───────────┬───────┬───────┘
              rlib (Rust dep)   │       │   staticlib + C ABI (FFI)
                    ┌───────────┴──┐  ┌─┴────────────────────────┐
                    │ packer (Rust)│  │ client (C++ + CMake)      │
                    │  czq-pack     │  │ Client + adapters M/V8    │
                    └──────────────┘  └───────────────────────────┘
```

Concordância byte-a-byte vira **propriedade de construção** (é o mesmo código). E o
núcleo nativo é exatamente o que se joga no VMProtect/OLLVM (RFC §11, §13).

### Layout do repositório

| Caminho | Papel |
|---|---|
| `spec/FORMAT.md` | contrato byte-a-byte (envelope, índice, manifest, derivação) |
| `docs/HARDENING.md` | evolução de segurança + resposta a red-team (o que endurecemos e por quê) |
| `docs/ROADMAP.md` | melhorias futuras ranqueadas por impacto real (servidor, VMProtect, watermark) |
| `crypto-core/` | núcleo Rust: cifras, KDFs, shares, per-sprite, manifest, **C ABI** |
| `packer/` | `czq-pack`: Argon2id, resolução de versão, `.spr`/`.dat`, seal, sign, codegen |
| `client/` | biblioteca C++ (interface estável), boot, adapters Mehah/V8, exemplo |
| `versions.xml` | tabela assinatura→versão (fornecida) |

---

## Estado: o que é real vs. costura de integração

**Implementado, compilando e testado (7 testes verdes + demo C++↔Rust):**

- Envelope unificado com header permutado + máscara XOR por build (RFC §8).
- 4 perfis: **A** AES-256-CTR/ChaCha20 + MAC por chunk, **B/D** AES-256-GCM,
  **C** CTR + MAC (RFC §8.2, D10–D13).
- Argon2id (raiz), HKDF-SHA256 (cold), BLAKE3 keyed (per-sprite, hot) — RFC §7.
- 4 shares XOR-mascaradas + reconstrução da `master'` ligada ao `integrity_material`
  (hash do manifest assinado) — RFC §7.1/§7.2/§7.3.
- Particionamento do `.spr` em chunks + **índice cifrado** + derivação per-sprite
  com canonicalização de `sub_ids` — RFC §9/§10.
- Manifest binário assinado com **Ed25519** + checagem de pubkey embutida — RFC §12.
- Resolução automática de versão do `versions.xml`, **com duas correções sobre a
  prosa da RFC** (ver abaixo) — RFC §6.1.
- `secure_zero` resistente ao compilador; boot sequence (RFC §14); interface C++
  estável; adapters finos Mehah e V8.
- **Criptografia de pasta inteira** (`packdir`): espelha a árvore do client, `.spr`
  vira `chunks/` no lugar, demais arquivos viram envelope no mesmo caminho.
- **Compressão zlib** compress-then-encrypt, condicional, por sprite e por arquivo.
- **GUI** (`czq-pack-gui`): pasta→pasta, gerar chave aleatória, compressão, log.

**Costura documentada (ferramentas proprietárias / árvores upstream — não
executável aqui, mas com os pontos de plugue prontos):**

- **VMProtect / OLLVM** (RFC §13, §17): marcadores em `client/include/czq/hardening.hpp`
  (`CZQ_VM_BEGIN/END`, `CZQ_OBFUSCATE`, `CZQ_IMAGE_CRC_OK`). O transform roda no CI
  sobre o binário; no-op em dev.
- **LuaJIT com opcodes remapeados** (RFC §11): o bytecode Lua já é protegido como
  cold (perfil B); o remap de opcodes exige o fork do LuaJIT no passo de build.
- **Parser completo de `.dat` para as 100+ versões**: implementado o suficiente para
  a cripto (largura u16/u32, particionamento); o enriquecimento de `sub_ids` por
  ThingType é ponto de extensão explícito em `packer/src/dat.rs::thing_context`. O
  pipeline **raw** já produz chave única e correta por sprite.

### Correções sobre a RFC §6.1 forçadas pelo `versions.xml`

1. **Largura do `dat` não é fixa em 4 bytes.** É 2 bytes a partir de **10.71**
   (`334F`, `3F26`, `42A3`…). Ler 4 bytes cegamente corrompe a detecção. O resolver
   é ciente da largura por linha da tabela.
2. **Assinatura não é única.** Há colisões totais (7.60/7.70, 10.60/10.61) e
   parciais. Lookup por assinatura dá um **conjunto de candidatos**; a corroboração
   estrutural é **obrigatória**, não opcional. (Testes em `packer/src/versions.rs`.)

---

## Build & teste

Pré-requisitos: Rust (1.75+), CMake (3.20+), MSVC (Windows) ou clang (OLLVM).

```bash
# 1) núcleo + packer + todos os testes (round-trip pack→unpack, resolver de versão)
cargo test

# 2) staticlib release do núcleo (o client C++ linka isto)
cargo build --release -p crypto-core

# 3) client C++ + demo
cmake -S client -B client/build -A x64
cmake --build client/build --config Release
```

### Fluxo de ponta a ponta (demonstração)

```bash
# gera um .spr sintético e empacota (Argon2 baixo só p/ demo)
./target/release/czq-pack.exe synth --out-spr in/Tibia.spr --count 60 --extended
./target/release/czq-pack.exe pack --spr in/Tibia.spr --cold in/hello.lua \
    --out out --passphrase "segredo" --versions versions.xml --chunk-size 16

# client C++ boota do out/ e descriptografa sprite + cold
./client/build/Release/czq_demo.exe out hello.lua 7
```

Saída real da demo (client C++ linkando o núcleo Rust):

```
booted. versions: dat=1098 spr=1098 features=0x7
sprite 7 decrypted: 19 bytes: FF 00 FF 0E 00 06 07 08 09 0A 0B 0C ...
cold 'hello.lua' decrypted: 47 bytes: 66 75 6E 63 74 69 6F 6E 20 ...   (= "function ...")
[mehah] setClientVersion(dat=1098 spr=1098 feat=0x7)
```

### CLI do packer

```
czq-pack detect --spr T.spr [--dat T.dat] [--versions versions.xml] [--force-version N]
czq-pack pack   --spr T.spr [--dat T.dat] [--otb items.otb] [--cold path]... \
                --out DIR --passphrase P [--versions versions.xml] [--force-version N]
                [--chunk-size 256] [--sprite-cipher aes-ctr|chacha20]
                [--argon-mcost-kib 262144] [--argon-tcost 4] [--argon-pcost 1]
czq-pack synth  --out-spr T.spr [--count N] [--spr-sig HEX] [--extended]   # p/ teste
```

Prefira `CZQ_PASSPHRASE` no ambiente em vez de `--passphrase` no shell.

Saída de `pack`: `manifest.czq`, `index.czq`, `<asset>.czq`, `spr_chunk_<id>.czq`, e
`embed/{material.bin, pubkey.bin, czq_build_material.h}`.

### Criptografar a pasta inteira do client (`packdir`)

Aponta para a pasta do client, varre **tudo recursivamente** e grava numa pasta de
saída **espelhando a árvore** (mesmos nomes/subpastas, porém criptografados). As
`.spr` são **particionadas** em uma pasta `chunks/` criada no lugar onde a `.spr`
estava; os demais arquivos viram um envelope no mesmo caminho.

```
czq-pack packdir --in <pasta_client> --out <pasta_saida> --passphrase P
                 [--versions versions.xml] [--force-version N]
                 [--sprite-cipher aes-ctr|chacha20] [--chunk-size 256]
                 [--no-compress]              # zlib é ligado por padrão
```

Exemplo de espelhamento:

```
entrada/                          saida/
├─ data/Tibia.spr        ──►      ├─ data/chunks/index.czq
├─ data/things/Tibia.dat          ├─ data/chunks/spr_chunk_0.czq
├─ modules/corelib.lua            ├─ data/things/Tibia.dat   (cifrado, mesmo nome)
└─ modules/game.otui              ├─ modules/corelib.lua     (cifrado + zlib)
                                  ├─ modules/game.otui
                                  ├─ manifest.czq
                                  └─ embed/{material.bin,pubkey.bin,czq_build_material.h}
```

**Compressão (zlib/deflate).** Ligada por padrão para sprites e arquivos textuais
(`.lua/.dat/.otui/.xml/…`), aplicada **antes** de cifrar (compress-then-encrypt,
`FLAG_COMPRESSED` do envelope §8) e **só quando reduz**. Mídia já comprimida
(`.png/.ogg/…`) é pulada. Exemplo real: `corelib.lua` 6600→121 B, `Tibia.dat`
15000→135 B (conteúdo repetitivo). LZMA fica como extensão (mais razão só em asset
grande, custo bem maior). No mirrored-layout o `.spr` inteiro **não** fica em RAM:
a descriptografia continua por chunk (RFC §10).

### Interface gráfica (GUI)

`czq-pack-gui.exe` (abre com duplo-clique) é uma janela sobre o `packdir`:

- **Pasta do client (entrada)** e **Pasta de saída** (seletores de pasta).
- **Gerar chave aleatória** (32 bytes → base64-url) + Mostrar/Copiar.
- Cifra de sprite, chunk, forçar versão, **checkbox de compressão zlib**, Argon2id
  (avançado), botões **Detectar versão** / **Criptografar pasta**, e um log ao vivo.

A GUI procura o `czq-pack.exe` na mesma pasta dela (ambos saem em `target/release/`).
A chave é passada por variável de ambiente ao processo filho (não aparece na lista de
processos).

```bash
cargo build --release            # gera czq-pack.exe e czq-pack-gui.exe
./target/release/czq-pack-gui.exe
```

---

## Integração no client (RFC §5.2 — regra de isolamento)

Cada adapter toca o upstream em **exatamente dois pontos** (e nada mais), atrás da
interface `czq::AssetSource`:

1. **Fonte de bytes** — `g_resources`/physfs devolve os bytes do envelope CZQ.
2. **Aplicação de versão** — após o boot, `setClientVersion(dat)` + features **antes**
   de qualquer parse de asset (RFC §14 passo 4).

```cpp
czq::mehah::MehahLoader loader(byteReader, versionApplier);
loader.boot(material, pubkey);              // §14: CRC → anti-debug → manifest → master'
loader.getSprite(id, out);                  // hook do SpriteManager
loader.getCold("Tibia.dat", out);           // hook do ThingTypeManager/ResourceManager
```

O material embutido (`czq_build_material.h`) é gerado pelo packer e compilado **antes**
do hardening (RFC §17 passo 4) — senão as constantes das shares ficam desprotegidas.

---

## Pipeline de build / CI (RFC §17 — ordem obrigatória)

Hardening é **sempre o último** passo sobre o binário:

1. Compilar LuaJIT customizado (opcodes remapeados).
2. Compilar cada loader (Mehah/V8) linkando `czq_client` + `crypto-core`.
3. Rodar `czq-pack` → asset set + `embed/`.
4. **Embutir `embed/czq_build_material.h`** no binário (codegen das 4 shares) —
   **antes** do hardening.
5. `cargo build --release -p crypto-core` e aplicar **VMProtect** (Windows) /
   **OLLVM** (mobile/Linux/mac) sobre o binário final (virtualizar as regiões
   marcadas: reconstrução da master, KDF de raiz, Ed25519, CRC/anti-debug).
6. Assinar/empacotar release. Cada run rotaciona `build_seed/build_salt/shares`.

**Rotação (RFC §16):** vazou → novo build, nova master, update forçado; o pacote
antigo morre. O updater do V8 é o canal grátis; no Mehah, definir o canal (item A2).

---

## Mapa RFC → código

| RFC | Onde |
|---|---|
| §6.1 resolução de versão | `packer/src/versions.rs` |
| §7 hierarquia de chaves, shares | `crypto-core/src/{shares,kdf,profile}.rs` |
| §8 envelope + perfis | `crypto-core/src/{format,cipher,profile}.rs` |
| §9 derivação per-sprite | `crypto-core/src/sprite.rs` |
| §10 particionamento `.spr` + índice | `packer/src/spr.rs`, `crypto-core/src/index.rs` |
| §12 manifest + Ed25519 | `crypto-core/src/manifest.rs`, `packer/src/manifest.rs` |
| §13 hardening | `client/include/czq/hardening.hpp` |
| §14 boot sequence | `client/src/client.cpp` (`Client::boot`) |
| §15 packer | `packer/src/pack.rs` |
| §17 CI / ordem | esta seção + `packer/src/codegen.rs` |

Itens em aberto da RFC §20 que continuam abertos: **A2** (canal de update do Mehah),
**A3** (N=4 shares — revisitável), **A4** (BLAKE3 vs HKDF no hot path — confirmar por
profiling).
