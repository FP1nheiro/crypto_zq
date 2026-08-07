// client.hpp — CZQ client facade (stable internal interface). Wraps the crypto-core
// C ABI and drives the boot sequence (RFC §14). The loader adapters call this; they
// never touch czq_core.h directly.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "asset_source.hpp"

struct CzqContext; // opaque (czq_core.h)

namespace czq {

struct Versions {
    uint16_t dat = 0;
    uint16_t spr = 0;
    uint32_t features = 0;
};

// Result of boot. On failure the client must degrade *non-obviously* (RFC §14) —
// callers should not print a clear "integrity failed" message.
enum class BootResult { Ok, IntegrityFailed, DebuggerDetected, ManifestInvalid, BadState };

class Client {
public:
    Client();
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Boot (RFC §14 steps 1–5): code-integrity + anti-debug seams, manifest verify,
    // master' reconstruction. `material` is the 177-byte assembled build material
    // (from czq_build_material.h); `pubkey` is the 32-byte embedded Ed25519 key.
    // `material` is securely wiped before returning.
    BootResult boot(AssetSource& source, std::vector<uint8_t>& material,
                    const uint8_t pubkey[32], const std::string& manifestName = "manifest.czq");

    bool booted() const { return ctx_ != nullptr; }
    const Versions& versions() const { return versions_; }

    // Load the encrypted sprite index (RFC §14 step 6). Call once after boot.
    bool loadSpriteIndex(const std::string& indexName = "index");

    // Decrypt a cold/ui/stream asset by manifest name (profiles B/C/D).
    bool decryptCold(const std::string& name, std::vector<uint8_t>& out);

    // Decrypt one sprite (profile A). Reads the owning chunk via the AssetSource,
    // verifies the chunk MAC once per chunk, then reuses `out`'s capacity across
    // calls (hot path). Zeroize `out` yourself once the pixels are uploaded.
    bool decryptSprite(uint32_t spriteId, std::vector<uint8_t>& out);

    // Wipe a buffer with the compiler-resistant core routine (RFC §7.4).
    static void secureZero(std::vector<uint8_t>& buf);
    static void secureZero(void* p, size_t n);

private:
    CzqContext* ctx_ = nullptr;
    AssetSource* source_ = nullptr;
    Versions versions_;

    // chunk-verification cache: MAC each chunk once, then skip (RFC §13 hot path).
    std::unordered_set<uint32_t> verifiedChunks_;
    uint32_t cachedChunkId_ = UINT32_MAX;
    std::vector<uint8_t> cachedChunk_;

    bool readChunk(uint32_t chunkId, const std::vector<uint8_t>*& bytes);
};

} // namespace czq
