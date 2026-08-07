// standalone_boot.cpp — runnable proof of the C++ client against a real packer
// output. Boots from embed/material.bin + embed/pubkey.bin + manifest.czq, loads
// the sprite index and decrypts a sprite + (optionally) a cold asset by name.
//
// Usage:  czq_demo <packer_out_dir> [cold_asset_name] [sprite_id]

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "czq/client.hpp"
#include "czq/file_source.hpp"
#include "mehah/mehah_adapter.hpp"

static bool readFile(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    if (n < 0) return false;
    out.resize(static_cast<size_t>(n));
    f.read(reinterpret_cast<char*>(out.data()), n);
    return static_cast<bool>(f);
}

static void hexDump(const std::vector<uint8_t>& b, size_t n) {
    n = n < b.size() ? n : b.size();
    for (size_t i = 0; i < n; ++i) std::printf("%02X ", b[i]);
    std::printf("%s\n", b.size() > n ? "..." : "");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: czq_demo <packer_out_dir> [cold_name] [sprite_id]\n");
        return 2;
    }
    std::string dir = argv[1];
    std::string coldName = argc >= 3 ? argv[2] : "";
    uint32_t spriteId = argc >= 4 ? static_cast<uint32_t>(std::stoul(argv[3])) : 1;

    std::printf("czq core format version: %u\n", 1u); // header constant is 1

    std::vector<uint8_t> material, pubkeyBuf;
    if (!readFile(dir + "/embed/material.bin", material) ||
        !readFile(dir + "/embed/pubkey.bin", pubkeyBuf) || pubkeyBuf.size() != 32) {
        std::printf("ERROR: missing embed/material.bin or embed/pubkey.bin in %s\n", dir.c_str());
        return 1;
    }
    uint8_t pubkey[32];
    std::copy(pubkeyBuf.begin(), pubkeyBuf.end(), pubkey);

    // --- boot via the stable Client facade ---
    czq::FileAssetSource source(dir);
    czq::Client client;
    czq::BootResult r = client.boot(source, material, pubkey);
    if (r != czq::BootResult::Ok) {
        std::printf("boot failed (code %d)\n", static_cast<int>(r));
        return 1;
    }
    const czq::Versions& v = client.versions();
    std::printf("booted. versions: dat=%u spr=%u features=0x%X\n", v.dat, v.spr, v.features);

    // --- sprite path ---
    if (!client.loadSpriteIndex()) {
        std::printf("failed to load sprite index\n");
        return 1;
    }
    std::vector<uint8_t> sprite;
    if (client.decryptSprite(spriteId, sprite)) {
        std::printf("sprite %u decrypted: %zu bytes: ", spriteId, sprite.size());
        hexDump(sprite, 12);
        czq::Client::secureZero(sprite); // §7.4 wipe after use
    } else {
        std::printf("sprite %u not found / failed\n", spriteId);
    }

    // --- cold path (optional) ---
    if (!coldName.empty()) {
        std::vector<uint8_t> cold;
        if (client.decryptCold(coldName, cold)) {
            std::printf("cold '%s' decrypted: %zu bytes: ", coldName.c_str(), cold.size());
            hexDump(cold, 32);
        } else {
            std::printf("cold '%s' not found / failed\n", coldName.c_str());
        }
    }

    // --- same thing through the Mehah adapter, to exercise the thin seam ---
    {
        czq::mehah::MehahLoader loader(
            [&](const std::string& name, std::vector<uint8_t>& out) { return source.read(name, out); },
            [](uint16_t dat, uint16_t spr, uint32_t feat) {
                std::printf("[mehah] setClientVersion(dat=%u spr=%u feat=0x%X)\n", dat, spr, feat);
            });
        std::vector<uint8_t> material2;
        readFile(dir + "/embed/material.bin", material2);
        if (loader.boot(material2, pubkey) == czq::BootResult::Ok) {
            std::vector<uint8_t> s;
            if (loader.getSprite(spriteId, s))
                std::printf("[mehah] sprite %u via adapter: %zu bytes\n", spriteId, s.size());
        }
    }

    std::printf("OK\n");
    return 0;
}
