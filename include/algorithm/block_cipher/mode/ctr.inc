#include <cstring>

#include "ctr.h"
#include "util/helper.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>&
CTR<BlockSizeBits, KeyBits, BufferSize>::operator<<(
    const std::vector<std::byte>& data) {
  if (this->output_buffer_full) {
    return *this;
  }

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
      std::array<std::byte, BlockSizeBits / 8> cipher_input_data;
      std::memcpy(cipher_input_data.data(), this->input_buffer.data(),
                  this->input_buffer.size());
      CipherAlgorithmReturnData result;
      if (this->mode == CipherMode::Encrypt) {
        cipher_input_data = file_encrypt::util::XorArrays<BlockSizeBits / 8>(
            cipher_input_data, this->prev_vector);
        result = this->cipher->Encrypt(cipher_input_data);
        std::memcpy(this->prev_vector.data(), result.data.data(),
                    this->prev_vector.size());
      } else {
        result = this->cipher->Decrypt(cipher_input_data);
        result.data = file_encrypt::util::XorVectors(
            std::vector<std::byte>(this->prev_vector.begin(),
                                   this->prev_vector.end()),
            result.data);
        std::memcpy(this->prev_vector.data(), cipher_input_data.data(),
                    this->prev_vector.size());
      }
      this->input_buffer_size = 0;

      OperationModeOutputData<BlockSizeBits> temp_result;
      std::memcpy(temp_result.data.data(), result.data.data(),
                  result.data.size());

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