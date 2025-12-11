#include <cstring>

#include "ctr.h"
#include "util/helper.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>&
CTR<BlockSizeBits, KeyBits, BufferSize>::operator<<(
    const std::span<const std::byte> data) {
  // if (this->output_buffer_full) {
  //   return *this;
  // }

  std::uint32_t remaining_input_bytes = data.size();
  std::uint32_t input_data_offset = 0;

  while (remaining_input_bytes > 0) {
    std::uint32_t bytes_to_copy =
        ((BlockSizeBits / 8) - this->input_buffer_size) < remaining_input_bytes
            ? (BlockSizeBits / 8) - this->input_buffer_size
            : remaining_input_bytes;

    std::memcpy(this->input_buffer.data() + this->input_buffer_size,
                data.data() + input_data_offset, bytes_to_copy);
    remaining_input_bytes -= bytes_to_copy;
    this->input_buffer_size += bytes_to_copy;
    input_data_offset += bytes_to_copy;

    // A block is complete at this point
    if (this->input_buffer_size == BlockSizeBits / 8) {
      std::array<std::byte, BlockSizeBits / 8> result =
          this->cipher->Encrypt(this->prev_vector);
      this->prev_vector =
          file_encrypt::util::StandardIncrement<16>(this->prev_vector, m);
      auto processed = file_encrypt::util::XorArrays<BlockSizeBits / 8>(
          result, this->input_buffer);

      this->input_buffer_size = 0;

      OperationModeOutputData<BlockSizeBits> temp_result;
      std::memcpy(temp_result.data.data(), processed.data(), processed.size());

      this->output_buffer[this->output_buffer_tail++] = temp_result;
      this->output_buffer_tail %= BufferSize;

      this->output_buffer_full =
          (this->output_buffer_tail == this->output_buffer_head);
    }
  }

  return *this;
}

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>&
CTR<BlockSizeBits, KeyBits, BufferSize>::operator>>(
    OperationModeOutputData<BlockSizeBits>& data) {
  std::memcpy(data.data.data(),
              this->output_buffer[this->output_buffer_head].data.data(),
              this->output_buffer[this->output_buffer_head].data.size());
  this->output_buffer_head++;
  this->output_buffer_head %= BufferSize;

  if (this->output_buffer_full) {
    this->output_buffer_full = false;
  }

  return *this;
}

};  // namespace file_encrypt::algorithm::op_mode