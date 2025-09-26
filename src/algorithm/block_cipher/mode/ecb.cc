#include "algorithm/block_cipher/mode/ecb.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr ECB<BlockSizeBits, KeyBits, BufferSize>&
ECB<BlockSizeBits, KeyBits, BufferSize>::operator<<(
    const std::vector<std::byte>& data) {
  if (output_buffer_full) {
    return ECB<BlockSizeBits, KeyBits, BufferSize>();
  }
}

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr ECB<BlockSizeBits, KeyBits, BufferSize>&
ECB<BlockSizeBits, KeyBits, BufferSize>::operator>>(
    const std::vector<std::byte>& data) {}

};  // namespace file_encrypt::algorithm::op_mode