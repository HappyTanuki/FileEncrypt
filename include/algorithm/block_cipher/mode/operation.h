#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_

#include <memory>

#include "algorithm/algorithm.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits>
struct OperationModeOutputData {
  std::array<std::byte, BlockSizeBits / 8> data = {};
};

enum class CipherMode { Encrypt, Decrypt };

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class OperationMode {
 public:
  OperationMode(std::unique_ptr<BlockCipherAlgorithm> algorithm,
                std::array<std::byte, KeyBits / 8> cipher_key = {},
                std::array<std::byte, BlockSizeBits / 8> initial_vector = {})
      : cipher(std::move(algorithm)), key(cipher_key), IV(initial_vector) {}
  virtual ~OperationMode() = default;

  virtual OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      const std::vector<std::byte>& data) = 0;
  OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      const CipherMode& mode) {
    this->mode = mode;
    return *this;
  }
  virtual OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator>>(
      OperationModeOutputData<BlockSizeBits>& data) = 0;

  constexpr std::uint32_t GetBufferCount() {
    if (this->output_buffer_full) {
      return BufferSize;
    } else if (this->output_buffer_tail >= this->output_buffer_head) {
      return this->output_buffer_tail - this->output_buffer_head;
    } else {
      return BufferSize - this->output_buffer_head + this->output_buffer_tail;
    }
  }

  constexpr void SetKey(const std::array<std::byte, KeyBits / 8>& cipher_key) {
    this->key = cipher_key;
  }
  constexpr void SetIV(
      std::array<std::byte, BlockSizeBits / 8> initial_vector) {
    this->IV = initial_vector;
  }

 protected:
  std::array<std::byte, BlockSizeBits / 8> IV;
  std::unique_ptr<BlockCipherAlgorithm> cipher;
  std::array<std::byte, KeyBits / 8> key;

  std::array<std::byte, BlockSizeBits / 8> input_buffer = {};
  std::uint32_t input_buffer_size = 0;

  std::array<OperationModeOutputData<BlockSizeBits>, BufferSize> output_buffer =
      {};
  std::uint32_t output_buffer_head = 0;
  std::uint32_t output_buffer_tail = 0;

  // To block input when output buffer is full
  bool output_buffer_full = false;

  CipherMode mode = CipherMode::Encrypt;
};

};  // namespace file_encrypt::algorithm::op_mode

#endif