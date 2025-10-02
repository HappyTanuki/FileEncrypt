#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <sstream>
#include <string>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s);

template <std::uint32_t Size>
std::string BytesToStr(const std::array<std::byte, Size>& bytes) {
  std::ostringstream osstream;

  for (int i = 0; i < Size; i++) {
    osstream << std::hex << std::to_integer<int>(bytes[i]);
  }

  return osstream.str();
}
std::string BytesToStr(const std::vector<std::byte>& bytes);

template <std::uint32_t Size>
std::array<std::byte, Size> HexStringToBytes(const std::string& hex) {
  std::array<std::byte, Size> bytes = {};

  for (size_t i = 0; i < hex.size(); i += 2) {
    bytes[i / 2] =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }

  return bytes;
}
std::vector<std::byte> HexStringToBytes(const std::string& hex);

}  // namespace file_encrypt::util

#endif