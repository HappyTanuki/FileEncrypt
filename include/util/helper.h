#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_HELPER_H_

#include <cstring>
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

// 덧셈 결과를 seedlen 비트로 자름
constexpr std::vector<std::byte> MaskSeedlen(
    const std::vector<std::byte>& value, const size_t& seedlen) {
  std::vector<std::byte> return_value = value;
  size_t byteLen = (seedlen + 7) / 8;
  size_t extraBits = seedlen % 8;
  if (extraBits != 0) {
    uint8_t mask = static_cast<uint8_t>((1 << extraBits) - 1);
    return_value[byteLen - 1] &= static_cast<std::byte>(mask);
  }

  if (return_value.size() > byteLen) {
    return_value.resize(byteLen);
  }

  return return_value;
}

std::vector<std::byte> UInt8ToBytesVector(uint64_t value);
std::vector<std::byte> UInt32ToBytesVector(uint64_t value);
std::vector<std::byte> UInt64ToBytesVector(uint64_t value);

template <typename... Vectors>
std::vector<std::byte> AddByteVectors(const std::vector<std::byte>& first,
                                      const Vectors&... rest) {
  static_assert((std::is_same_v<Vectors, std::vector<std::byte>> && ...),
                "All arguments must be std::vector<std::byte>");
  std::array<const std::vector<std::byte>*, sizeof...(rest) + 1> all = {
      &first, &rest...};

  size_t byteLen = 0;
  for (auto v : all) byteLen = std::max(byteLen, v->size());

  std::vector<std::byte> result(byteLen);
  uint16_t carry = 0;

  for (size_t i = 0; i < byteLen; ++i) {
    uint16_t sum = carry;
    for (auto v : all) {
      if (i < v->size()) sum += static_cast<uint8_t>((*v)[i]);
    }
    result[i] = static_cast<std::byte>(sum & 0xFF);
    carry = sum >> 8;
  }

  if (carry) result.push_back(static_cast<std::byte>(carry));

  return result;
}

template <typename... Vectors>
std::vector<std::byte> ConcatByteVectors(Vectors&&... vecs) {
  size_t total_size = (vecs.size() + ... + 0);
  std::vector<std::byte> result;
  result.reserve(total_size);
  (result.insert(result.end(), std::make_move_iterator(vecs.begin()),
                 std::make_move_iterator(vecs.end())),
   ...);
  return result;
}

std::vector<std::byte> Leftmost(const std::vector<std::byte>& value,
                                const std::uint64_t& size);

constexpr std::string GetEnglishNumberSufix(std::uint64_t number) {
  std::string result;
  if (number % 10 == 1 && number != 11) {
    result = "st";
  } else if (number % 10 == 2 && number != 12) {
    result = "nd";
  } else if (number % 10 == 3 && number != 13) {
    result = "rd";
  } else {
    result = "th";
  }

  return result;
}

}  // namespace file_encrypt::util

#endif