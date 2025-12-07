#include <algorithm>
#include <cstring>

#include "algorithm/padding/pkcs_7.h"

namespace file_encrypt::algorithm {

template <std::uint32_t BlockSize>
std::vector<std::array<std::byte, BlockSize / 8>>
Pkcs_7<BlockSize>::MakePaddingBlock(std::vector<std::byte> data) {
  std::uint32_t bytes_left = data.size() + this->buffer_index;
  std::uint32_t last_block_len = bytes_left % (BlockSize / 8);
  std::uint8_t padding_number = BlockSize / 8 - last_block_len;
  std::vector<std::array<std::byte, BlockSize / 8>> result = {};
  std::array<std::byte, BlockSize / 8> padding_bytes = {};

  for (int i = BlockSize / 8 - 1; i >= last_block_len; i--) {
    padding_bytes[i] = static_cast<std::byte>(padding_number);
  }

  std::uint32_t offset = 0;

  while (bytes_left >= BlockSize / 8) {
    std::uint32_t bytes_to_copy = BlockSize / 8 - this->buffer_index;
    std::memcpy(this->buffer.data() + this->buffer_index, data.data() + offset,
                bytes_to_copy);
    result.push_back(this->buffer);
    bytes_left -= bytes_to_copy;
    offset += bytes_to_copy;
    this->buffer_index = 0;
  }
  std::memcpy(padding_bytes.data(), data.data() + offset, bytes_left);
  result.push_back(padding_bytes);

  return result;
}

template <std::uint32_t BlockSize>
RemovePaddingReturnData<BlockSize> Pkcs_7<BlockSize>::RemovePadding(
    std::vector<std::byte> data) {
  std::array<std::byte, BlockSize / 8> result = {};
  std::uint32_t bytes_to_copy =
      BlockSize / 8 - std::to_integer<int>(data[data.size() - 1]);

  data.resize(bytes_to_copy);
  std::memcpy(result.data(), data.data(), data.size());

  return {result, bytes_to_copy};
}

};  // namespace file_encrypt::algorithm