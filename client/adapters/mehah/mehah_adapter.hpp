// mehah_adapter.hpp — thin loader for OTClient Mehah (opentibiabr). RFC §5.1/§5.2.
//
// Isolation rule (RFC §5.2): this is the ONLY file that knows about both CZQ and
// Mehah. It plugs into Mehah at exactly two seams and nowhere else, so an upstream
// update can't scatter-break the integration:
//
//   1. Byte source  — `g_resources.readFileContents(path)` (ResourceManager) feeds
//      FunctionAssetSource. In Mehah the .spr/.dat load goes through
//      SpriteManager / ThingTypeManager; point those at getSprite()/getCold().
//   2. Version apply — after boot, call the applier which does the equivalent of
//      `g_things.setClientVersion(dat)` + feature enables (RFC §14 step 4) BEFORE
//      any asset is parsed.
//
// This header compiles standalone (no Mehah headers) by taking the two seams as
// std::function; real integration binds them to the upstream calls.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "czq/client.hpp"
#include "czq/file_source.hpp"

namespace czq::mehah {

class MehahLoader {
public:
    // seam 1: pull raw bytes for a resource name (bind to g_resources).
    using ByteReader = std::function<bool(const std::string&, std::vector<uint8_t>&)>;
    // seam 2: apply resolved versions to the Mehah parser (bind to g_things/g_game).
    using VersionApplier = std::function<void(uint16_t dat, uint16_t spr, uint32_t features)>;

    MehahLoader(ByteReader reader, VersionApplier applier)
        : source_(std::move(reader)), applyVersion_(std::move(applier)) {}

    // RFC §14: boot, then push versions into the Mehah parser before assets load.
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

    // Hook target for SpriteManager: return decrypted sprite block bytes.
    bool getSprite(uint32_t spriteId, std::vector<uint8_t>& out) {
        return client_.decryptSprite(spriteId, out);
    }
    // Hook target for ThingTypeManager / ResourceManager (Lua, .dat, UI).
    bool getCold(const std::string& name, std::vector<uint8_t>& out) {
        return client_.decryptCold(name, out);
    }

    Client& client() { return client_; }

private:
    Client client_;
    FunctionAssetSource source_;
    VersionApplier applyVersion_;
};

} // namespace czq::mehah
