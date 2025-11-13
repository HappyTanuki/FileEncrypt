#include <fstream>

#include "key_loader.h"

namespace file_encrypt::util {

template <std::uint32_t KeySize>
std::array<std::byte, KeySize> KeyStore(
    const std::filesystem::path& file_path) {
  std::ofstream file(file_path);
}

template <std::uint32_t KeySize>
std::array<std::byte, KeySize> KeyLoad(const std::filesystem::path& file_path) {
  std::ifstream file(file_path);
}

};  // namespace file_encrypt::util