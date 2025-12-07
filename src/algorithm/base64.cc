#include "algorithm/base64.h"

#include <algorithm>

#include "util/helper.h"

namespace file_encrypt::algorithm {

std::vector<std::byte> BASE64::Encoding(
    const std::vector<std::byte>& data) const {
  if (data.size() == 0) return {};

  std::vector<std::byte> encoded((data.size() + 2) / 3 * 4);

  size_t i = 0, j = 0;
  while (i < data.size()) {
    std::uint32_t word_bytes[3];
    word_bytes[0] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    word_bytes[1] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    word_bytes[2] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    std::uint32_t word =
        word_bytes[0] << 16 | word_bytes[1] << 8 | word_bytes[2];

    encoded[j++] = static_cast<std::byte>(kBase64Chars[(word >> 18) & 0x3F]);
    encoded[j++] = static_cast<std::byte>(kBase64Chars[(word >> 12) & 0x3F]);
    encoded[j++] = static_cast<std::byte>(kBase64Chars[(word >> 6) & 0x3F]);
    encoded[j++] = static_cast<std::byte>(kBase64Chars[word & 0x3F]);
  }

  size_t mod = data.size() % 3;
  if (mod > 0) {
    encoded[encoded.size() - 1] = static_cast<std::byte>('=');
    if (mod == 1) {
      encoded[encoded.size() - 2] = static_cast<std::byte>('=');
    }
  }

  return encoded;
}

std::vector<std::byte> BASE64::Decoding(
    const std::vector<std::byte>& data) const {
  std::vector<std::byte> decoded((data.size() + 3) / 4 * 3);

  size_t i = 0, j = 0;
  while (i < data.size()) {
    std::uint32_t word_bytes[4];
    word_bytes[0] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    word_bytes[1] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    word_bytes[2] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;
    word_bytes[3] = i < data.size() ? static_cast<std::uint8_t>(data[i++]) : 0;

    std::uint32_t word = (word_bytes[0] & 0x3F) << 18 |
                         (word_bytes[1] & 0x3F) << 12 |
                         (word_bytes[2] & 0x3F) << 6 | (word_bytes[3] & 0x3F);

    if (data[i - 2] != static_cast<std::byte>('='))
      decoded[j++] = static_cast<std::byte>((word >> 16) & 0xFF);
    if (data[i - 1] != static_cast<std::byte>('='))
      decoded[j++] = static_cast<std::byte>((word >> 8) & 0xFF);
    if (data[i] != static_cast<std::byte>('='))
      decoded[j++] = static_cast<std::byte>(word & 0xFF);
  }
  return decoded;
}

std::vector<std::byte> BASE64::Decoding(const std::string& data) const {
  return Decoding(ReplaceChar(data));
}

std::vector<std::byte> BASE64::ReplaceChar(std::vector<std::byte> data) const {
  std::transform(data.begin(), data.end(), data.begin(), [this](std::byte c) {
    return kIBase64[static_cast<std::uint8_t>(c)];
  });
  return data;
}

std::vector<std::byte> BASE64::ReplaceChar(const std::string& data) const {
  return ReplaceChar(file_encrypt::util::StrToBytes(data));
}

}  // namespace file_encrypt::algorithm