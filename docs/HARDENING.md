# CZQ — Endurecimento e resposta a red-team

Este documento registra a evolução de segurança do CZQ **depois** da RFC base, guiada
por análises de red-team reais. A regra que organiza tudo: **conte segredos, não
camadas.** Rearranjar cifras, keys e camadas dentro do binário é profundidade de
derivação, não segredo novo.

## O teto honesto (o teorema)

O atacante é o **destinatário**: o client precisa desenhar o sprite e rodar o Lua,
então em algum instante o conteúdo existe em claro na RAM. Criptografia local não
guarda segredo de quem tem o client — ela só **eleva o custo**. Nenhuma cifra, número
de keys ou container (exe/dll/lib) muda isso. As duas únicas coisas que mudam a
*natureza* do problema:

1. **A key não morar no client** (segredo entregue pelo servidor no login).
2. **O código de derivação da key ser ilegível** (virtualização — VMProtect/OLLVM
   sobre `czq_boot`/reconstrução do master).

Tudo abaixo é *altura de degrau* dentro do modelo client-only — melhorias reais, mas
não muros.

## O que foi endurecido (todas sem servidor, salvo nota)

### Anti-análise (o que mais custou ao red-team)
- **Strip de metadados do Rust.** Os paths de panic (`kdf.rs`, `shares.rs`, `sprite.rs`)
  e as versões de crate entregavam a arquitetura inteira num `strings`. Corrigido com
  `panic="abort"` + `strip=true` + `--remap-path-prefix` (mata o path pessoal do
  usuário, em `.cargo/config.toml`) e, no build de release, nightly
  `-Zlocation-detail=none -Zfmt-debug=none` (remove nomes de módulo e versões de crate).
  Verificado: `Trintt`, `kdf.rs`, `aes-0.8.4` → 0 no `.lib`.
- **Constantes de domínio em bytes crus.** As labels da KDF eram hex ASCII (faróis no
  `.rdata`); viraram `[u8;32]` opacos (`K_SEED_TERM`, `K_HEADER`, …) e o
  `derive_key(str)` virou `keyed_hash(raw)`. Nada de crypto aparece no `strings`.

### Controle de acesso (fecha o dumper fácil)
- **Allowlist de `.otmod` (anti-injeção).** O furo: arquivo fora do manifest caía em
  leitura crua → dava pra injetar um módulo novo que chamava `readFileContents()`
  (exposto ao Lua) e despejava tudo já decriptado. Agora o manifest assinado é
  **allowlist de execução**: um `.otmod` fora do manifest é recusado (só quando módulos
  foram empacotados — `czq_has_asset_suffix(".otmod")`). Isento `/bot/` e `/downloads`.
  Recomendação fora de código: não empacotar o módulo `client_terminal` no release.

### Confidencialidade e remoção de oráculos
- **Manifest cifrado.** O índice (nomes+ids) era texto assinado, legível. Agora é
  cifrado (AES-256-CTR, chave do `build_seed`, decifrado no `czq_boot` antes de
  verificar a assinatura Ed25519). Também resolve "tire os ids do manifest".
- **Índice de sprite denso, sem oráculos.** Antes: 27 B/sprite com 4 confirmações
  grátis (`0xff`=RAW, `sub_count=1`, `assembled_id==id`, `offset==prev+size`) — o
  atacante batia esses e sabia que tinha decifrado certo. Agora: só um varint de
  `size` por id; `sprite_id`/`chunk_id`/`offset`/contexto RAW são reconstruídos da
  posição. Sem magic (o envelope já é GCM-autenticado). Zero campo redundante,
  ~2 B/sprite em dados densos.

### Proteção de conteúdo Lua
- **Remap de opcodes do LuaJIT.** Bytecode é empacotado com os opcodes permutados por
  build (derivado do `build_seed`) e des-permutado dentro do `czq_decrypt_cold`. O
  packer compila `.lua` source → bytecode (via um `luajit.exe` **embutido** no
  `czq-pack.exe` — sem vcpkg) pra cobertura de 100%. Quem quebra a cifra extrai
  bytecode embaralhado, que não roda no LuaJIT stock nem abre em decompiler. Fase 1
  (opcional, requer LuaJIT patchado) move a des-permutação pra própria VM — o bytecode
  stock nunca materializa.

### Compartimentalização de key (prep pro futuro)
- **Duas keys separadas.** Key X (arquivos/cold) vem do `master` (das shares + hash do
  manifest); key Y (sprites) é um `sprite_secret` de 32 bytes **independente**, embutido
  no material. As duas árvores não saem de uma raiz só. Hoje ambas moram no binário —
  **sem ganho** contra quem tem o client — mas a separação deixa a key Y pronta pra
  virar segredo do login com **uma linha**: `master_sprites = HKDF(sprite_secret,
  segredo_do_servidor)`, sem tocar nos arquivos.
- **Rotação de cipher por build.** `--sprite-cipher random` (padrão na GUI) sorteia
  AES-CTR ou ChaCha20 por pacote e grava no manifest — força o atacante a suportar os
  dois. AES e ChaCha são equivalentes em segurança; a escolha é performance/plataforma.

## O que foi recusado (com motivo)

- **Empilhar cifras (AES+Camellia+Serpent) / cascata / DLL / mais keys no binário.** A
  cifra protege contra quem **não tem** a key; o atacante **tem** a key (tem o client).
  Empilhar defende contra o atacante errado e custa FPS + superfície de auditoria. DLL
  ainda piora (fronteira de exports = hook trivial via proxy-DLL). AES-256 sozinho já é
  inquebrável pra quem só tem o ciphertext.

## O que muda a natureza (fora do escopo atual)

- **VMProtect / OLLVM virtualizando `czq_boot`** — "semanas, não horas". O único
  movimento client-only que sobe o degrau de verdade. Documentado no client
  (`HARDENING_VMPROTECT.md`).
- **Segredo do servidor no login** — a key deixa de morar no client; um dump estático
  vira "impossível sem conta". Contradiz o requisito RFC D3 (sem key server) — é uma
  decisão de produto, não uma linha de código a mais na crypto.
- **Lógica no servidor + watermark por conta** — o muro real é a lógica que nunca sai
  do servidor; pra arte, atribuição (quem vazou) dissuade mais que prevenção.
