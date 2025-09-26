#include "algorithm/block_cipher/mode/ecb.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>&
ECB<BlockSizeBits, KeyBits, BufferSize>::operator<<(
    const std::vector<std::byte>& data) {
  if (this->output_buffer_full) {
    return *this;
  }

  std::uint32_t remaining_input_bytes = data.size();
  std::uint32_t input_data_offset = 0;

  CipherAlgorithmInputData cipher_input_data;
  cipher_input_data.key = this->key;

  while (remaining_input_bytes > 0) {
    std::uint32_t bytes_to_copy = ((BlockSizeBits / 8) - this->input_buffer_size) < remaining_input_bytes
            ? (BlockSizeBits / 8) - this->input_buffer_size : remaining_input_bytes;
    std::memcpy(this->input_buffer.data() + this->input_buffer_size,
                data.data() + input_data_offset, bytes_to_copy);
    remaining_input_bytes -= bytes_to_copy;
    this->input_buffer_size += bytes_to_copy;
    input_data_offset += bytes_to_copy;

    if (this->input_buffer_size == BlockSizeBits / 8) {
      cipher_input_data.data = this->input_buffer;
      auto result = this->cipher(cipher_input_data);
      this->input_buffer_size = 0;

      this->output_buffer[this->output_buffer_tail++] =
          OperationModeOutputData(result);
      this->output_buffer_tail %= BufferSize;

      this->output_buffer_full = (this->output_buffer_tail == this->output_buffer_head);
    }
  }

  return *this;
}

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>&
ECB<BlockSizeBits, KeyBits, BufferSize>::operator>>(
    OperationModeOutputData<BlockSizeBits>& data) {
  data = this->output_buffer[this->output_buffer_head++];
  this->output_buffer_head %= BufferSize;

  if (this->output_buffer_full) {
    this->output_buffer_full = false;
  }

  return *this;
}

};  // namespace file_encrypt::algorithm::op_mode