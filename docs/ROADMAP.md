# CZQ — Melhorias futuras (ranqueadas por impacto real)

Este documento é a bússola estratégica: **o que vale investir**, em ordem de quanto
sobe o custo do atacante — não de quão sofisticado parece. Baseado em análises de
red-team reais (ver [`HARDENING.md`](HARDENING.md)).

> A régua única: uma melhoria só conta se dá ao atacante **algo que ele genuinamente
> não possui** — uma key que ele não recebe, ou código que ele não consegue ler.
> Rearranjar cifras/keys/camadas dentro do binário não move o ponteiro.

## Tier 1 — muda a natureza do problema

### 1. Segredo do servidor no login
A key deixa de morar 100% no client. Um dump estático vira "impossível sem conta".
- **Como:** `master_sprites = HKDF(sprite_secret, segredo_do_servidor)`. O terreno já
  está pronto — a key Y (sprites) já é um tronco independente (ver `context.rs`).
- **Escopo:** conteúdo pós-login (sprites, `.dat`, `.lua` do jogo). O framework
  pré-login (tela de login) fica na key embutida por necessidade técnica.
- **Custo:** adição modesta no TFS (guardar o segredo, entregá-lo no login autenticado).
  **Não** exige mover lógica. Contradiz o requisito RFC D3 (sem key server) — é decisão
  de produto.
- **Efeito:** o único movimento que converte "reversível numa sessão" em "precisa de
  credencial válida".

### 2. Virtualizar `czq_boot` (VMProtect Ultimate ou OLLVM)
Torna o código de reconstrução do master **ilegível/não-executável isolado**.
- **Como:** VMProtect virtualiza `czq_boot` + reconstrução do master + hooks; de brinde
  vem anti-debug e `VMProtectIsValidImageCRC` (amarra à `.text`, quebra dumpers que
  patcheiam o binário). Alternativa grátis: isolar a reconstrução num TU C++ e passar
  OLLVM só nele. Guia no client: `HARDENING_VMPROTECT.md`.
- **Efeito:** o red-team lê disassembly linear e segue panic strings; contra código
  virtualizado isso "vira semanas, não horas". É o maior movimento **sem servidor**.
- **Preparo já feito:** os seams estão prontos (boot isolado, strings/paths já
  limpos); é apontar o obfuscador pra `czq_boot`.

## Tier 2 — degraus reais, client-only

- **Lua Fase 1 (LuaJIT patchado des-permuta na VM).** Move a des-permutação de opcodes
  pro próprio LuaJIT — o bytecode stock nunca materializa. Requer buildar o LuaJIT do
  client com o patch. Já implementado no packer (`--lua-vm-perm` gera `lj_czq_perm.h`);
  o patch + workflow estão em `LUA_VM_PATCH.md` (client).
- **KDF amarrado ao hash da `.text`** (se não for usar VMProtect). Quebra dumper que
  patcheia o binário. Precisa de um passo pós-build que hasheia a `.text` e resolve as
  shares — frágil; o `VMProtectIsValidImageCRC` faz isso pronto, então prefira o Tier 2
  via VMProtect.

## Tier 3 — o que realmente importa proteger (reframe)

Assets são copiáveis por teorema — pare de pagar complexidade por eles. O muro real é
a **lógica**, que não precisa estar no client:

- **Lógica sensível no servidor autoritativo** (balanceamento, anti-cheat, detecção,
  endpoints). O que não está no client não vaza do client. É muro de verdade, não custo.
- **Watermark por conta na arte.** Troca prevenção por *atribuição*: não impede o
  vazamento, identifica quem vazou — dissuade mais, porque o custo cai sobre um nome.

## Explicitamente NÃO fazer (already-answered)

- Empilhar cifras (AES+Camellia+Serpent) / cascata — a cifra protege contra quem não
  tem a key; o atacante tem a key. AES-256 sozinho já é inquebrável pra quem só tem o
  ciphertext.
- Mover a crypto pra uma DLL — fronteira de exports = hook trivial via proxy-DLL. Pior
  que o estático fundido no exe.
- Mais keys/shares/camadas dentro do binário — profundidade de derivação não cria
  segredo.

## Rotação (operacional, contínuo)

Cada `packdir`/`pack` rotaciona `build_seed`, `sprite_secret`, shares, permutação Lua e
o cipher de sprite. Vazou? Novo pack + recompila + distribui pelo updater; o dump antigo
morre no build novo. É a defesa estratégica barata da RFC — mantenha frequente.
