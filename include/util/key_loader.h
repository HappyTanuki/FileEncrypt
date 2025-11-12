#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_KEY_LOADER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_KEY_LOADER_H_

#include <array>
#include <cstdint>
#include <filesystem>

namespace file_encrypt::util {

template <std::uint32_t KeySize>
std::array<std::byte, KeySize> KeyLoad(const std::filesystem::path& file_path);

};

#include "key_loader.inc"

#endif