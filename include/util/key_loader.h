#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_KEY_LOADER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_KEY_LOADER_H_

#include <array>
#include <cstdint>
#include <filesystem>

namespace file_encrypt::util {

template <std::uint32_t KeySize>
void KeyStore(const std::filesystem::path& file_path,
              std::array<std::byte, KeySize / 8> key,
              const std::string& algorithm_name);

template <std::uint32_t KeySize>
std::array<std::byte, KeySize / 8> KeyLoad(
    const std::filesystem::path& file_path, const std::string& algorithm_name);

template <std::uint32_t KeySize>
void KeyStore(std::ostream* stream,
              const std::array<std::byte, KeySize / 8>& key,
              const std::string& algorithm_name);

template <std::uint32_t KeySize>
std::array<std::byte, KeySize / 8> KeyLoad(std::istream* stream,
                                           const std::string& algorithm_name);

};  // namespace file_encrypt::util

#include "key_loader.inc"

#endif