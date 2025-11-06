#include "util/helper.h"

#include <algorithm>
#include <cstdint>
#include <sstream>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result;
  result.reserve(s.size());
  for (char c : s) result.push_back(static_cast<std::byte>(c));
  return result;
}

std::vector<std::byte> HexStrToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::vector<std::byte> XorVectors(const std::vector<std::byte>& a,
                                  const std::vector<std::byte>& b) {
  std::vector<std::byte> result;
  if (a.size() < b.size()) {
    return result;
  }
  result.resize(a.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    result[i] = static_cast<std::byte>(static_cast<unsigned char>(a[i]) ^
                                       static_cast<unsigned char>(b[i]));
  }
  return result;
}

std::vector<std::byte> UInt8ToBytesVector(uint64_t value) {
  std::vector<std::byte> result(1);
  result[0] = static_cast<std::byte>(value & 0xFF);
  return result;
}

std::vector<std::byte> UInt32ToBytesVector(uint64_t value) {
  std::vector<std::byte> result(4);
  for (size_t i = 0; i < 4; ++i) {
    result[3 - i] = static_cast<std::byte>(value & 0xFF);
    value >>= 8;
  }
  return result;
}

std::vector<std::byte> Leftmost(const std::vector<std::byte>& value,
                                const std::uint64_t& size) {
  std::vector<std::byte> result;
  size_t byteLen = (size + 7) / 8;
  result.resize(byteLen);
  std::memcpy(result.data(), value.data(), byteLen);

  std::uint32_t extraBits = size % 8;
  if (extraBits != 0) {
    // 예: extraBits = 3 → 상위 3비트만 남기고 나머지는 0으로
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - extraBits));
    result.back() &= static_cast<std::byte>(mask);
  }

  return result;
}

// incomplete, only for size multiple of 8
std::vector<std::byte> Rightmost(const std::vector<std::byte>& value,
                                 const std::uint64_t& size) {
  std::vector<std::byte> result;
  result.resize(size / 8);

  std::uint32_t offset = std::max<size_t>(value.size() - size / 8, 0);

  std::memcpy(result.data(), value.data() + offset, size / 8);

  return result;
}

}  // namespace file_encrypt::util