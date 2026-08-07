# RFC v1.0 — Subsistema de Criptografia e Anti-Tamper do Client

**Status:** Consolidado (pronto para virar especificação byte-a-byte)
**Servidor:** TFS
**Clients-alvo:** OTClient Mehah (opentibiabr) · OTClientV8 (OTCv8) — o OTAV8 é espelho do V8 e usa o mesmo loader
**Modelo:** raiz de confiança embutida no client, derivação local, sem key server
**Regra de versionamento:** este documento e o campo `container.version` sobem juntos. Trocar algoritmo exige bump de versão.

---

## 1. Objetivo e não-objetivos

**Objetivo:** elevar o custo de reversão/extração de assets acima do valor percebido, com resposta a incidente por rotação de build.

**Não-objetivos (para calibrar expectativa):**
- Não é inquebrável. Contra reverser avançado com tooling próprio, o alvo é semanas de trabalho, não bloqueio permanente.
- Nenhum esquema client-side resiste a um dump de RAM perfeitamente sincronizado. Mitigamos a janela (zeroize) e virtualizamos a raiz, não prometemos impossibilidade.

---

## 2. Modelo de ameaça e teto de segurança

| Atacante | Ferramenta | Barrado por |
|---|---|---|
| Curioso / usuário | editor hex, unpacker genérico | envelope + cripto real + header por build |
| Reverser intermediário | x64dbg, Cheat Engine, dumpers | VMProtect/OLLVM, shares, zeroize, virtualização |
| Reverser avançado | tooling custom, unpack de VMProtect | **passa** → resposta = rotação de build |

**Teto sem servidor:** a raiz vive no binário → comprometimento total de um build é possível para o avançado. Defesa estratégica = **rotação por build barata e frequente**, embutida no pipeline desde o dia 1.

---

## 3. Log de decisões (todas resolvidas)

| # | Decisão | Escolha | Justificativa |
|---|---|---|---|
| D1 | Servidor | TFS | definido |
| D2 | Clients | Mehah + OTClientV8 (V8 cobre OTAV8) | OTAV8 é espelho do V8 → 2 famílias, não 3 |
| D3 | Origem da raiz | embutida no client, derivação local | requisito: nenhuma key vem do servidor |
| D4 | Hardening desktop Windows | VMProtect (virtualização + mutation) | PE/Windows; melhor ROI contra reversão |
| D5 | Hardening mobile/Linux/Mac | OLLVM (Obfuscator-LLVM) | VMProtect não cobre ARM/Linux |
| D6 | KDF de raiz | Argon2id (offline, no packer) | memory-hard; roda 1x; trava brute-force da passphrase |
| D7 | Split da master | 4 shares XOR-mascaradas | suficiente vs. `grep` de entropia; Shamir é overkill |
| D8 | KDF cold | HKDF-SHA256 | padrão, auditável |
| D9 | KDF hot (por-sprite) | BLAKE3 keyed | rápido; volume em tempo real não paga HMAC |
| D10 | Cipher sprite (desktop) | AES-256-CTR | AES-NI acelera em hardware |
| D11 | Cipher sprite (mobile/ARM) | ChaCha20 | sem AES-NI no ARM → ChaCha ganha |
| D12 | Cipher cold/UI | AES-256-GCM | AEAD, autenticação por arquivo |
| D13 | Autenticação de sprite | MAC por **chunk**, não por sprite | por sprite mataria o framerate |
| D14 | Assinatura | Ed25519 (manifest) | detecta troca de qualquer arquivo |
| D15 | Integridade de código | `VMProtectIsValidImageCRC` (Win) / checagem própria (mobile) | não usar hash de `.text` no binding (ver §7.2) |
| D16 | Formato de asset | .dat/.spr clássico, versão **parametrizável** | denominador comum entre Mehah e V8 |
| D17 | Bytecode Lua | LuaJIT com opcodes remapeados + cifrado | quebra decompile público |
| D18 | Arquitetura multi-client | **spec única + 1 loader por família** | packer produz um asset set; adaptadores finos |

---

## 4. Arquitetura geral

```
┌─ PACKER (offline, app externo — Rust) ───────────────────┐
│  passphrase → Argon2id → master_key (1x)                 │
│  gera: 4 shares mascaradas, build_seed, build_salt       │
│  cifra assets por perfil (envelope unificado)            │
│  particiona .spr em chunks + índice cifrado              │
│  gera manifest + assina (Ed25519)                        │
│  emite: asset set único + material embutido no build     │
└──────────────────────────────────────────────────────────┘
             │ asset set (.dat/.spr clássico protegido)
             ▼
┌─ CLIENT — 1 spec, 2 loaders ─────────────────────────────┐
│  Loader Mehah  →  hook em SpriteManager/ThingType        │
│  Loader V8     →  hook em physfs/ResourceManager         │
│                                                          │
│  BOOT: CRC código → valida manifest (Ed25519)            │
│        → reconstrói master' [VIRTUALIZADO]               │
│  RUN:  deriva per_asset_key (JIT) → usa → zeroize        │
└──────────────────────────────────────────────────────────┘
```

---

## 5. Estratégia multi-client (spec única + 2 loaders)

**Princípio:** o formato (envelope, KDF, shares, derivação) é **portátil e único**. Só o adaptador que pluga no pipeline varia. O packer produz **um asset set**, consumido pelas duas famílias.

### 5.1 Hook points por família

| Família | Camada de hook | Observação |
|---|---|---|
| **Mehah** (opentibiabr) | `SpriteManager` / `ThingTypeManager`; `ResourceManager` para módulos/Lua | C++20; definir canal de distribuição de update |
| **OTClientV8** (OTCv8/OTAV8) | camada **physfs** / `ResourceManager` | **já tem cripto nativa (data.zip) — substituir** pelo nosso esquema; updater próprio existente |

### 5.2 Regra de isolamento

Cada loader é um **adaptador fino** atrás de uma interface interna estável, tocando o mínimo do código upstream. Mehah (4.1, ativo) e V8 (auto-update por CI) evoluem — não espalhe a integração pelo código deles, senão cada update upstream quebra o hook.

### 5.3 Matriz de hardening por plataforma

| Plataforma | Hardening de binário | Cipher de sprite | Nível |
|---|---|---|---|
| Windows desktop | VMProtect (virtualização + mutation) | AES-256-CTR (AES-NI) | completo |
| Linux desktop | OLLVM | AES-256-CTR (AES-NI) | médio |
| Android / ARM (V8) | OLLVM + strip NDK | ChaCha20 | mais fraco → compensar com rotação |
| macOS | OLLVM | AES-256-CTR ou ChaCha20 | médio |

A **cripto de assets é idêntica** em todas; só o hardening do executável muda.

---

## 6. Formato de asset (denominador comum)

- **`.dat/.spr` clássico**, não o formato moderno de appearances/protobuf — é o que o V8 exige e o Mehah também carrega.
- A **versão do `.dat/.spr` é auto-detectada pelo packer** (o TFS pode variar de versão entre setups), não hard-coded nem setada à mão. A versão fixa a estrutura de flags do `.dat`, o tamanho dos ids de sprite (u16 vs u32 em 9.60+) e a montagem de sub-sprites.
- **Criticidade:** a versão é *load-bearing* pra cripto — versão errada → `sub_ids` errados → `per_sprite_key` errada → descriptografia falha. Packer e client **obrigatoriamente** concordam na versão; o manifest assinado é o que garante isso.

### 6.1 Resolução automática de versão (no packer)

Em ordem de confiança, com fallback (no OT, assinatura editada/spoofada é comum):

1. **Assinaturas:** lê `datSignature`/`sprSignature` (4 B) → resolve numa **tabela assinatura→versão** mantida.
2. **Corroboração estrutural:** confere contagem de sprites do `.spr` + parse do `.dat`; a versão certa parseia sem overrun e com o stream de atributos terminando limpo.
3. **Probing:** se a assinatura for desconhecida, testa versões candidatas e escolhe a que passa na corroboração.
4. **Override explícito:** flag opcional na config pra forçar versão em assets muito customizados — único ponto manual, usado só se a auto-detecção falhar.

A versão resolvida (`dat_version`, `spr_version`, `feature_flags`) é **carimbada no manifest assinado** (§12).

**Distinção obrigatória:** versão do **asset** (`.dat/.spr`, fixada no pack time, importa pra cripto) ≠ versão de **protocolo** negociada no login com o TFS (runtime, rede). Devem bater, mas o parsing acopla ao manifest, nunca ao handshake de login.

---

## 7. Hierarquia de chaves e componentes Tier 2

### 7.1 Fluxo de chaves

```
passphrase do dev ──Argon2id──► master_key   (SÓ no packer, offline)

[no client, reconstruída em runtime — nunca inteira em disco]
share_1..4 (mascaradas) ⊕ build_seed ⊕ integrity_material
        └─ combine dentro de rotina VIRTUALIZADA ─► master'  (transiente)
                                                       │ HKDF-SHA256 (cold) / BLAKE3 (hot)
                                                       ▼
                              per_asset_key  (JIT, zeroize após uso)
```

**Regra inegociável:** `master_key` nunca existe como blob contíguo de 32 bytes no binário. É reconstruída das 4 shares dispersas.

### 7.2 Binding por integridade — **atenção ao conflito com o packer**

O VMProtect reescreve/cifra o binário. `hash(.text)` em runtime **quebra**. Resolução:
- `integrity_material` = **hash de assets read-only estáveis** (o manifest assinado / blob de recurso que não passa pela transformação do packer). Adulterar asset → `master'` errada → descriptografia falha sozinha (sem checagem "nopável").
- Integridade do **código** = `VMProtectIsValidImageCRC()` (Windows) / rotina própria ofuscada (mobile), como gate separado. Defesa em profundidade sem os dois se atrapalharem.

### 7.3 Key splitting

- **N=4 shares**, cada uma XORada com máscara derivada de outra constante do build, espalhadas em seções distintas (`.rodata`, recursos, constantes de funções diferentes).
- Combine por XOR em runtime, **dentro da rotina virtualizada**.

### 7.4 JIT + zeroize

- `per_asset_key` derivada no momento do uso, nunca em lote.
- Após descriptografar: `secure_zero` (resistente à otimização do compilador) na key e no buffer. Minimiza a janela em RAM.

---

## 8. Envelope unificado e perfis por tipo

### 8.1 Layout lógico (ordem física permutada por `build_seed`)

| Campo | Tam. | Descrição |
|---|---|---|
| `magic` | 4 B | variável por build (derivado de `build_seed`) |
| `version` | 1 B | versão do formato — **obrigatório** |
| `asset_type` | 1 B | seleciona perfil A/B/C/D |
| `flags` | 1 B | compressão etc. |
| `salt`/`nonce` | 12–16 B | por asset |
| `payload_len` | 4 B | tamanho do payload cifrado |
| `payload` | var | dados cifrados |
| `auth_tag` | 16 B | tag AEAD (B/D) ou MAC de chunk (A/C) |

### 8.2 Perfis

| Perfil | Assets | Cipher | Autenticação |
|---|---|---|---|
| **A – Hot** | sprites | AES-256-CTR (desktop) / ChaCha20 (mobile) | **MAC por chunk** (ex.: bloco de 256 sprites) |
| **B – Cold** | bytecode Lua, .dat, .otb | AES-256-GCM | tag GCM por arquivo |
| **C – Stream** | sons, música | AES-256-CTR em blocos | MAC por bloco |
| **D – UI** | PNG, fontes, OTUI | AES-256-GCM | tag GCM por arquivo |

### 8.3 Headers variáveis por build

Determinístico por build: `build_seed` define `magic`, a permutação da ordem dos campos e uma máscara XOR de ofuscação do header. O client daquela versão reverte. É ofuscação (camada), nunca pilar.

---

## 9. Derivação da key de sprite (sob demanda, local)

```
per_sprite_key = KDF(
    key  = master',
    salt = build_salt,
    info = category_byte(1)         // item / outfit / effect / missile
         || assembled_id (LE32)     // id da sprite montada
         || sorted(sub_ids)(LE32[]) // ids das subsprites, ORDENADOS
)[0:32]
```

- **KDF = BLAKE3 keyed** neste hot path (D9). HKDF-SHA256 fica para índice/cold.
- **Ordenar `sub_ids`** (canonicalização) → key idêntica independente da ordem de leitura. Sem isso: bug intermitente de render.
- Derivação lazy por sprite requisitada, zeroize após uso. Nada vem da rede.

---

## 10. Particionamento do .spr

- `.spr` fatiado em **chunks** de tamanho fixo (ex.: 256 sprites).
- **Índice cifrado** (perfil B) mapeia `sprite_id → (chunk, offset, sub_ids)`. Carregado no boot.
- MAC por chunk (perfil A). Nunca há o `.spr` inteiro descriptografado em disco.

---

## 11. Proteção do bytecode Lua

1. **LuaJIT recompilado com opcodes remapeados** → quebra decompile público.
2. **Bytecode cifrado** (perfil B, AES-256-GCM) → descriptografa em RAM → `luaL_loadbuffer`.
3. **Migrar lógica sensível** (validação, cálculo de key, anti-cheat) de Lua para **C++** dentro das regiões protegidas. O que não é Lua não é decompilável como Lua.

Honestidade: o buffer descriptografado existe em RAM antes do load; breakpoint em `luaL_loadbuffer` o dumpa. As camadas custam dias ao avançado e barram ~95% dos curiosos.

---

## 12. Integridade e assinatura

- **Manifest assinado com Ed25519.** Packer assina (privada offline); client valida com a **pública embutida** no boot (região virtualizada). Cobre inclusive arquivos não cifrados (UI).
- **Campos de versão no manifest:** `dat_version`, `spr_version` e `feature_flags` resolvidos pela auto-detecção (§6.1). Por estarem sob a assinatura, são à prova de adulteração e são a fonte da verdade que o client usa para configurar o parser antes de carregar assets.
- **Código:** `VMProtectIsValidImageCRC` (Win) / rotina própria (mobile).

---

## 13. Camada de hardening de binário

### 13.1 VMProtect (Windows) — o que virtualizar

Virtualização é 10–1000x mais lenta → só rotinas **pequenas, frias e críticas**.

| Região | Modo | Motivo |
|---|---|---|
| Reconstrução da master (combine de shares) | Virtualização (Ultra) | boot, 1x |
| Setup do KDF de raiz | Virtualização | boot |
| Validação Ed25519 | Virtualização | boot |
| CRC / anti-debug | Virtualização | pontual |
| Parser do header do envelope | Mutation | frequência moderada |
| **Derivação por-sprite (BLAKE3)** | **não proteger** | hot path — 200+/frame |
| **Loop de descriptografia de sprite** | **não proteger** | precisa AES-NI/paralelismo |

Habilitar também: string encryption, import protection, memory protection, debugger detection (filtro de amador — bypass existe).

### 13.2 OLLVM (mobile/Linux/Mac)

Sem VMProtect na plataforma. Aplicar control-flow flattening + string encryption + bogus control flow via OLLVM nas mesmas regiões críticas. Aceitar que mobile é intrinsecamente mais fraco no binário → compensar com rotação.

---

## 14. Sequência de boot

1. Integridade do código (`VMProtectIsValidImageCRC` / rotina própria) → aborta se adulterado.
2. Detecção de debugger → resposta **discreta** (degradar/atrasar, não abortar com mensagem óbvia).
3. Carregar e validar manifest (Ed25519) — virtualizado.
4. **Ler `dat_version`/`spr_version`/`feature_flags` do manifest e configurar o parser do ThingType/sprite** (equivalente a `setClientVersion()` + enable de features) **antes** de tocar em qualquer asset. Mesmo caminho nos dois loaders (Mehah e V8 ramificam parsing por versão/feature).
5. Reconstruir `master'`: localizar 4 shares, desmascarar, combinar com `build_seed` e `integrity_material` — virtualizado.
6. Carregar índice de sprites cifrado (perfil B).
7. Runtime: derivação JIT por asset, zeroize após uso.

**Falha de integridade nunca aborta de forma clara** — prefira falha atrasada e não-determinística (corromper derivação, travar adiante). Dificulta localizar o ponto de checagem.

---

## 15. Packer (pipeline offline — Rust)

1. `passphrase` → **Argon2id** → `master_key`.
2. Gerar `build_salt`, `build_seed`; dividir a master em **4 shares mascaradas**.
3. Por asset: selecionar perfil, derivar key, cifrar, montar envelope com header permutado.
4. Particionar `.spr` em chunks + índice cifrado.
5. Gerar manifest, assinar (**Ed25519**).
6. Emitir: asset set único + material embutido (shares espalhadas, `build_seed`, `build_salt`, pública Ed25519).

Único lugar com a lógica de master. O client só contém material de reconstrução. Rodável N vezes → cada run gera keys novas.

---

## 16. Rotação e resposta a incidente

**Defesa estratégica principal do Tier 2 sem servidor.**

- Cada build: `build_seed`/`build_salt`/`shares` novos → dump do build anterior vira inútil.
- Vazamento → **novo build, nova master, update forçado**. Pacote antigo morre.
- **Sinergia V8:** o OTClientV8 já tem updater próprio → é o **canal de distribuição** dos builds rotacionados de graça. No Mehah, definir esse canal (item aberto A2).

---

## 17. Pipeline de build / CI (por plataforma)

Ordem obrigatória — hardening é o **último** passo sobre o binário:

1. Compilar LuaJIT customizado (opcodes remapeados).
2. Compilar cada loader (Mehah / V8) com marcadores nas regiões críticas.
3. Rodar o **packer** → asset set + material do build.
4. Embutir material do build no binário (codegen das 4 shares mascaradas) — **antes** do hardening.
5. Aplicar hardening: **VMProtect** (Windows) ou **OLLVM** (mobile/Linux/Mac).
6. Assinar/empacotar release.

**Gotcha de ordem:** material embutido (passo 4) entra antes do VMProtect (passo 5), senão as constantes das shares ficam desprotegidas.

---

## 18. Roadmap de implementação

1. **Envelope + Cold:** container versionado + perfil B (AES-GCM) para Lua/dat + manifest Ed25519.
2. **Sprites:** particionamento .spr, perfil A (AES-CTR/ChaCha20 + MAC por chunk), derivação por-sprite (BLAKE3).
3. **Raiz Tier 2:** 4 shares, binding por integridade, JIT + zeroize.
4. **Bytecode:** LuaJIT remapeado + migração de lógica sensível p/ C++.
5. **Hardening:** VMProtect (Win) / OLLVM (mobile) + CRC + string/import protection no CI.
6. **Loaders:** adaptador Mehah e adaptador V8 sobre a mesma spec.

Cada fase entrega valor sozinha.

---

## 19. Matriz de riscos

| Risco | Impacto | Mitigação |
|---|---|---|
| Raiz no client | comprometimento total de build | rotação agressiva; VMProtect na reconstrução |
| Virtualização no hot path | queda de FPS | virtualizar só cold/crítico; sprites nunca |
| Self-hash × packer | descriptografia quebra | binding em assets read-only; CRC do VMProtect p/ código |
| Dois upstreams evoluindo | loader quebra a cada update | adaptador fino e isolado, interface estável |
| Mobile sem VMProtect | binário mais fraco | OLLVM + rotação; aceitar teto menor |
| White-box caseiro (se tentado) | falsa confiança | **não fazer**; Tier 2 + hardening substitui |
| LuaJIT fork | manutenção ao atualizar upstream | isolar patch de opcodes; documentar rebase |

---

## 20. Assunções e itens em aberto

- **A1 — RESOLVIDO:** versão do `.dat/.spr` é **auto-detectada pelo packer** (§6.1) e carimbada no manifest assinado; override manual só como escape para assets com assinatura spoofada. Não bloqueia mais o build.
- **A2 — canal de update do Mehah:** o V8 tem updater; o Mehah precisa de um definido para a rotação funcionar como resposta a incidente.
- **A3 — N de shares (4) e esquema de máscara:** revisitável se profiling/segurança pedir.
- **A4 — BLAKE3 vs HKDF no hot path:** decidido BLAKE3; confirmar por profiling na Fase 2.

Com **A1** resolvido (auto-detecção), a especificação byte-a-byte do `.dat`, do `.spr` e do índice de sprites já pode ser escrita — parametrizada pelas versões que a tabela assinatura→versão suportar, não presa a uma única versão.
