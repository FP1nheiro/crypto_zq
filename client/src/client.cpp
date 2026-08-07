// client.cpp — CZQ client facade implementation. Drives the boot sequence
// (RFC §14) and wraps the crypto-core C ABI. Keeps the hot-path buffer reuse and
// per-chunk MAC caching here so the adapters stay trivial.

#include "czq/client.hpp"
#include "czq/hardening.hpp"
#include "czq_core.h"

#include <functional>

namespace czq {

namespace {
// Two-call buffer protocol against the C ABI, reusing `out`'s capacity. On the
// hot path (sprites) the reserved capacity almost always fits in one call; only a
// larger-than-expected asset triggers the resize + single retry.
using AbiCall = std::function<int32_t(uint8_t*, size_t, size_t*)>;

int32_t callOut(std::vector<uint8_t>& out, const AbiCall& fn) {
    if (out.capacity() < 4096) {
        out.reserve(4096);
    }
    out.resize(out.capacity());
    size_t need = 0;
    int32_t rc = fn(out.data(), out.size(), &need);
    if (rc == CZQ_ERR_SHORT_BUFFER) {
        out.resize(need);
        rc = fn(out.data(), out.size(), &need);
    }
    out.resize(rc == CZQ_OK ? need : 0);
    return rc;
}
} // namespace

Client::Client() = default;

Client::~Client() {
    if (ctx_) {
        czq_free(ctx_);
        ctx_ = nullptr;
    }
    secureZero(cachedChunk_);
}

void Client::secureZero(void* p, size_t n) {
    czq_secure_zero(static_cast<uint8_t*>(p), n);
}
void Client::secureZero(std::vector<uint8_t>& buf) {
    if (!buf.empty()) {
        czq_secure_zero(buf.data(), buf.size());
    }
}

BootResult Client::boot(AssetSource& source, std::vector<uint8_t>& material,
                        const uint8_t pubkey[32], const std::string& manifestName) {
    // The whole boot is a candidate VMProtect Ultra region (RFC §13.1).
    CZQ_VM_BEGIN("czq_boot");

    // §14.1 code integrity. On failure prefer a delayed, non-obvious death — here
    // we simply refuse to produce a context, so decryption fails "on its own"
    // downstream rather than at an obvious check (RFC §7.2, §14).
    if (!CZQ_IMAGE_CRC_OK()) {
        CZQ_VM_END();
        return BootResult::IntegrityFailed;
    }
    // §14.2 debugger detection — discrete response (caller degrades, no loud abort).
    if (CZQ_DEBUGGER_PRESENT()) {
        CZQ_VM_END();
        return BootResult::DebuggerDetected;
    }

    // §14.3 load + verify manifest; §14.5 reconstruct master' (both inside czq_boot).
    std::vector<uint8_t> manifest;
    if (!source.read(manifestName, manifest)) {
        CZQ_VM_END();
        return BootResult::ManifestInvalid;
    }
    int32_t rc = czq_boot(material.data(), material.size(), manifest.data(),
                          manifest.size(), pubkey, &ctx_);

    // §7.4 minimize the RAM window for the embedded material.
    secureZero(material);
    CZQ_VM_END();

    if (rc != CZQ_OK || !ctx_) {
        ctx_ = nullptr;
        return BootResult::ManifestInvalid;
    }

    // §14.4 read version fields → the adapter configures the parser before assets.
    czq_versions(ctx_, &versions_.dat, &versions_.spr, &versions_.features);
    source_ = &source;
    return BootResult::Ok;
}

bool Client::loadSpriteIndex(const std::string& indexName) {
    if (!ctx_ || !source_) {
        return false;
    }
    uint64_t id = 0;
    if (czq_asset_id_by_name(ctx_, indexName.c_str(), &id) != CZQ_OK) {
        return false;
    }
    std::vector<uint8_t> env;
    if (!source_->read(indexName + ".czq", env)) {
        return false;
    }
    return czq_load_index(ctx_, id, env.data(), env.size()) == CZQ_OK;
}

bool Client::decryptCold(const std::string& name, std::vector<uint8_t>& out) {
    if (!ctx_ || !source_) {
        return false;
    }
    uint64_t id = 0;
    if (czq_asset_id_by_name(ctx_, name.c_str(), &id) != CZQ_OK) {
        return false;
    }
    std::vector<uint8_t> env;
    if (!source_->read(name + ".czq", env)) {
        return false;
    }
    return callOut(out, [&](uint8_t* o, size_t cap, size_t* need) {
               return czq_decrypt_cold(ctx_, id, env.data(), env.size(), o, cap, need);
           }) == CZQ_OK;
}

bool Client::readChunk(uint32_t chunkId, const std::vector<uint8_t>*& bytes) {
    if (chunkId == cachedChunkId_ && !cachedChunk_.empty()) {
        bytes = &cachedChunk_;
        return true;
    }
    secureZero(cachedChunk_);
    cachedChunk_.clear();
    if (!source_->read(AssetSource::chunkName(chunkId) + ".czq", cachedChunk_)) {
        cachedChunkId_ = UINT32_MAX;
        return false;
    }
    cachedChunkId_ = chunkId;
    bytes = &cachedChunk_;
    return true;
}

bool Client::decryptSprite(uint32_t spriteId, std::vector<uint8_t>& out) {
    if (!ctx_ || !source_) {
        return false;
    }
    uint32_t chunkId = 0;
    if (czq_chunk_of(ctx_, spriteId, &chunkId) != CZQ_OK) {
        return false;
    }
    const std::vector<uint8_t>* chunk = nullptr;
    if (!readChunk(chunkId, chunk)) {
        return false;
    }
    const int32_t verify = verifiedChunks_.count(chunkId) ? 0 : 1;
    int32_t rc = callOut(out, [&](uint8_t* o, size_t cap, size_t* need) {
        return czq_decrypt_sprite(ctx_, spriteId, chunk->data(), chunk->size(), verify, o, cap, need);
    });
    if (rc == CZQ_OK && verify) {
        verifiedChunks_.insert(chunkId);
    }
    return rc == CZQ_OK;
}

} // namespace czq
