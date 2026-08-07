// asset_source.hpp — the stable seam between CZQ and each client family (RFC §5.2).
//
// The loader adapters (Mehah, OTClientV8) implement *only* this interface: "give
// me the raw bytes of a logical asset name". Everything else — key handling,
// envelope parsing, decryption — lives behind czq::Client and never leaks into the
// upstream client code, so an upstream update can't break the crypto integration.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace czq {

// Abstract byte provider. `name` is a logical asset name:
//   - "manifest.czq", "index"            → control assets
//   - a manifest asset name, e.g. "Tibia.dat"
//   - "spr_chunk_<id>"                    → sprite chunk files
// The adapter maps the name to its storage (filesystem, physfs, ResourceManager)
// and returns the exact on-disk bytes.
class AssetSource {
public:
    virtual ~AssetSource() = default;

    // Returns true and fills `out` on success; false if the asset is absent.
    virtual bool read(const std::string& name, std::vector<uint8_t>& out) = 0;

    // Chunk-file name convention shared with the packer (spr_chunk_<id>).
    static std::string chunkName(uint32_t chunkId) {
        return "spr_chunk_" + std::to_string(chunkId);
    }
};

} // namespace czq
