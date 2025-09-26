#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <string>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result;
  result.reserve(s.size());
  for (char c : s) result.push_back(static_cast<std::byte>(c));
  return result;
}

template <std::uint32_t Size>
std::array<std::byte, Size> HexStringToBytes(const std::string& hex) {
  std::array<std::byte, Size> bytes;

  for (size_t i = 0; i < Size; i += 2) {
      bytes[i] =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }

  return bytes;
}

std::vector<std::byte> HexStringToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

}  // namespace file_encrypt::util

#endif