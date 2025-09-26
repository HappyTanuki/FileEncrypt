#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_

#include <memory>

#include "algorithm/algorithm.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits>
struct OperationModeOutputData {
  std::array<std::byte, BlockSizeBits / 8> data = {};
};

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class OperationMode {
 public:
  OperationMode(std::unique_ptr<BlockCipherAlgorithm> algorithm,
                std::array<std::byte, KeyBits / 8> cipher_key,
                std::array<std::byte, BlockSizeBits / 8> initial_vector = {})
      : cipher(std::move(algorithm)), key(cipher_key), IV(initial_vector) {}
  virtual ~OperationMode() = default;

  OperationMode& operator<<(const std::vector<std::byte>& data) = 0;
  OperationMode& operator>>(OperationModeOutputData<BlockSizeBits>& data) = 0;

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
};

};  // namespace file_encrypt::algorithm::op_mode

#endif