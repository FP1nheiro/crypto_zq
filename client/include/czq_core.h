/* czq_core.h — C ABI for the CZQ crypto-core (Rust staticlib).
 *
 * This is the ONLY surface between the C++ client and the crypto. Everything
 * below is implemented once, in Rust (crypto-core), and shared with the packer,
 * so packer and client agree byte-for-byte by construction (RFC §6).
 *
 * Link against czq_core.lib plus: bcrypt advapi32 kernel32 ntdll userenv ws2_32
 * dbghelp (see CMakeLists.txt).
 */
#ifndef CZQ_CORE_H
#define CZQ_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque runtime context (holds master', codec, index). Free with czq_free. */
typedef struct CzqContext CzqContext;

/* Status codes. 0 = success; others mirror crypto_core::error::Error. */
enum {
    CZQ_OK = 0,
    CZQ_ERR_TRUNCATED = 1,
    CZQ_ERR_BAD_FORMAT = 2,
    CZQ_ERR_AUTH_FAILED = 3,
    CZQ_ERR_BAD_SIGNATURE = 4,
    CZQ_ERR_NOT_FOUND = 5,
    CZQ_ERR_SHORT_BUFFER = 6,
    CZQ_ERR_UNSUPPORTED = 7
};

/* Format version implemented by this core build. */
uint32_t czq_format_version(void);

/* Boot (RFC §14): verify manifest under `pubkey` (32 bytes), reconstruct master'.
 * On success writes a heap handle to *out_ctx. */
int32_t czq_boot(const uint8_t* material, size_t material_len,
                 const uint8_t* manifest, size_t manifest_len,
                 const uint8_t* pubkey, CzqContext** out_ctx);

/* Version fields resolved from the signed manifest (RFC §14 step 4). Any out ptr
 * may be NULL. */
int32_t czq_versions(CzqContext* ctx, uint16_t* dat_version,
                     uint16_t* spr_version, uint32_t* feature_flags);

/* Resolve a logical asset name (from the manifest table) to its id. */
int32_t czq_asset_id_by_name(CzqContext* ctx, const char* name, uint64_t* out_id);

/* Decrypt a cold/ui/stream envelope (profiles B/C/D).
 * Buffer protocol: if `out` is NULL or `out_cap` is too small, returns
 * CZQ_ERR_SHORT_BUFFER and writes the needed length to *out_len. */
int32_t czq_decrypt_cold(CzqContext* ctx, uint64_t asset_id,
                         const uint8_t* envelope, size_t envelope_len,
                         uint8_t* out, size_t out_cap, size_t* out_len);

/* Load + decrypt the sprite index (kept in RAM inside the context). */
int32_t czq_load_index(CzqContext* ctx, uint64_t asset_id,
                       const uint8_t* envelope, size_t envelope_len);

/* Chunk id holding `sprite_id` (so the caller knows which chunk file to read). */
int32_t czq_chunk_of(CzqContext* ctx, uint32_t sprite_id, uint32_t* out_chunk);

/* Decrypt one sprite from its chunk bytes (profile A). `verify` != 0 checks the
 * per-chunk MAC (do it once per chunk, then pass 0). Same buffer protocol as
 * czq_decrypt_cold. */
int32_t czq_decrypt_sprite(CzqContext* ctx, uint32_t sprite_id,
                           const uint8_t* chunk, size_t chunk_len, int32_t verify,
                           uint8_t* out, size_t out_cap, size_t* out_len);

/* Free a context. */
void czq_free(CzqContext* ctx);

/* Compiler-resistant memory wipe (RFC §7.4). */
void czq_secure_zero(uint8_t* ptr, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CZQ_CORE_H */
