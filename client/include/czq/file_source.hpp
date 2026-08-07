// file_source.hpp — concrete AssetSource implementations (header-only).
//   * FileAssetSource     — reads from a directory (example / tests / CLI tools).
//   * FunctionAssetSource — adapts any `std::function` byte reader, so a loader
//                           adapter can plug an upstream ResourceManager/physfs
//                           call in without subclassing.
#pragma once

#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include "asset_source.hpp"

namespace czq {

class FileAssetSource : public AssetSource {
public:
    explicit FileAssetSource(std::string dir) : dir_(std::move(dir)) {}

    bool read(const std::string& name, std::vector<uint8_t>& out) override {
        std::string path = dir_;
        if (!path.empty() && path.back() != '/' && path.back() != '\\') {
            path += '/';
        }
        path += name;
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            return false;
        }
        f.seekg(0, std::ios::end);
        std::streamoff n = f.tellg();
        f.seekg(0, std::ios::beg);
        if (n < 0) {
            return false;
        }
        out.resize(static_cast<size_t>(n));
        f.read(reinterpret_cast<char*>(out.data()), n);
        return static_cast<bool>(f);
    }

private:
    std::string dir_;
};

class FunctionAssetSource : public AssetSource {
public:
    using Reader = std::function<bool(const std::string&, std::vector<uint8_t>&)>;
    explicit FunctionAssetSource(Reader r) : reader_(std::move(r)) {}

    bool read(const std::string& name, std::vector<uint8_t>& out) override {
        return reader_ ? reader_(name, out) : false;
    }

private:
    Reader reader_;
};

} // namespace czq
