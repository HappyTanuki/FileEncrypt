#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <iomanip>
#include <sstream>
#include <string>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s);

template <typename Container>
std::string BytesToStr(const Container& bytes) {
  std::ostringstream osstream;

  for (auto b : bytes) {
    osstream << std::uppercase << std::setw(2) << std::setfill('0') << std::hex
             << std::to_integer<int>(b);
  }

  return osstream.str();
}

std::vector<std::byte> HexStringToBytes(const std::string& hex);
template <std::uint32_t Size>
std::array<std::byte, Size> HexStringToBytes(const std::string& hex) {
  std::array<std::byte, Size> bytes = {};

  for (size_t i = 0; i < hex.size(); i += 2) {
    bytes[i / 2] =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }

  return bytes;
}

std::vector<std::byte> XorVectors(const std::vector<std::byte>& a,
                                  const std::vector<std::byte>& b);

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> XorArrays(
    const std::array<std::byte, Size>& a,
    const std::array<std::byte, Size>& b) {
  std::array<std::byte, Size> result;
  for (std::size_t i = 0; i < Size; ++i) {
    result[i] = static_cast<std::byte>(static_cast<unsigned char>(a[i]) ^
                                       static_cast<unsigned char>(b[i]));
  }
  return result;
}

template <std::uint32_t Size>
constexpr std::array<std::byte, Size> StandardIncrement(
    const std::array<std::byte, Size>& array, const int& m) {
  std::array<std::byte, Size> result = array;

  std::uint32_t counter_bytes = (m + 7) / 8;
  bool carry = false;

  int i = Size - 1;
  do {
    if (result[i] != static_cast<std::byte>(0xFF)) {
      std::uint8_t t = std::to_integer<std::uint8_t>(result[i]);
      t += 1;
      result[i] = static_cast<std::byte>(t);
    } else {
      result[i] = static_cast<std::byte>(0x00);
      carry = true;
    }
  } while (carry && --i >= counter_bytes);

  return result;
}

}  // namespace file_encrypt::util

#endif