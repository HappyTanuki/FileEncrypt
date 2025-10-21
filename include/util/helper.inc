#include <cstdint>
#include <sstream>
#include <vector>

#include "util/helper.h"

namespace file_encrypt::util {

constexpr std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result;
  result.reserve(s.size());
  for (char c : s) result.push_back(static_cast<std::byte>(c));
  return result;
}

template <typename Container>
std::string BytesToStr(const Container& bytes) {
  std::ostringstream osstream;

  for (auto b : bytes) {
    osstream << std::uppercase << std::setw(2) << std::setfill('0') << std::hex
             << std::to_integer<int>(b);
  }

  return osstream.str();
}

constexpr std::vector<std::byte> HexStringToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}
template <std::uint32_t Size>
constexpr std::array<std::byte, Size> HexStringToBytes(const std::string& hex) {
  std::array<std::byte, Size> bytes = {};

  for (size_t i = 0; i < hex.size(); i += 2) {
    bytes[i / 2] =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }

  return bytes;
}

constexpr std::vector<std::byte> XorVectors(const std::vector<std::byte>& a,
                                            const std::vector<std::byte>& b) {
  std::vector<std::byte> result;
  if (a.size() != b.size()) {
    return result;
  }
  result.resize(a.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    result[i] = static_cast<std::byte>(static_cast<unsigned char>(a[i]) ^
                                       static_cast<unsigned char>(b[i]));
  }
  return result;
}

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
    if (result[i] != 0xFF) {
      result[i] += 1;
    } else {
      result[i] = 0x00;
      carry = true;
    }
  } while (carry && --i >= counter_bytes);

  return result;
}

}  // namespace file_encrypt::util