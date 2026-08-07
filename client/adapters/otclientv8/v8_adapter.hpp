// v8_adapter.hpp — thin loader for OTClientV8 (OTCv8 / OTAV8). RFC §5.1/§5.2.
//
// V8 already ships native crypto (the data.zip / physfs layer). This adapter
// REPLACES it (RFC §5.1): instead of physfs reading cleartext out of data.zip,
// route reads through CZQ. Two seams, same isolation rule as the Mehah adapter:
//
//   1. Byte source  — the physfs / ResourceManager read (PHYSFS_openRead + read,
//      or g_resources) feeds FunctionAssetSource.
//   2. Version apply — after boot, apply resolved versions to V8's parser
//      (g_things.setClientVersion + g_game features) before assets load.
//
// V8's own updater is the free rotation channel (RFC §16): ship each rotated build
// (new shares/seed/salt) through it.
//
// Compiles standalone; bind the seams to the real physfs calls in integration.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "czq/client.hpp"
#include "czq/file_source.hpp"

namespace czq::v8 {

class V8Loader {
public:
    using ByteReader = std::function<bool(const std::string&, std::vector<uint8_t>&)>;
    using VersionApplier = std::function<void(uint16_t dat, uint16_t spr, uint32_t features)>;

    V8Loader(ByteReader reader, VersionApplier applier)
        : source_(std::move(reader)), applyVersion_(std::move(applier)) {}

    BootResult boot(std::vector<uint8_t>& material, const uint8_t pubkey[32]) {
        BootResult r = client_.boot(source_, material, pubkey);
        if (r == BootResult::Ok) {
            const Versions& v = client_.versions();
            if (applyVersion_) {
                applyVersion_(v.dat, v.spr, v.features);
            }
            client_.loadSpriteIndex();
        }
        return r;
    }

    // Hook target where physfs would have returned a sprite/resource.
    bool getSprite(uint32_t spriteId, std::vector<uint8_t>& out) {
        return client_.decryptSprite(spriteId, out);
    }
    bool getCold(const std::string& name, std::vector<uint8_t>& out) {
        return client_.decryptCold(name, out);
    }

    Client& client() { return client_; }

private:
    Client client_;
    FunctionAssetSource source_;
    VersionApplier applyVersion_;
};

} // namespace czq::v8
