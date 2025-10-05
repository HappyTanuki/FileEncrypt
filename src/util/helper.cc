#include "util/helper.h"

#include <cstdint>
#include <sstream>
#include <vector>

namespace file_encrypt::util {

std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result;
  result.reserve(s.size());
  for (char c : s) result.push_back(static_cast<std::byte>(c));
  return result;
}

std::string BytesToStr(const std::vector<std::byte>& bytes) {
  std::ostringstream osstream;

  for (int i = 0; i < bytes.size(); i++) {
    osstream << std::hex << std::to_integer<int>(bytes[i]);
  }

  return osstream.str();
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

std::vector<std::byte> XorVectors(const std::vector<std::byte>& a,
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

}  // namespace file_encrypt::util