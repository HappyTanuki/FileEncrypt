#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_CTR_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_CTR_H_

#include "operation.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class CTR : public OperationMode<BlockSizeBits, KeyBits, BufferSize> {
 public:
  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::OperationMode;
  CTR(std::unique_ptr<BlockCipherAlgorithm<KeyBits, BlockSizeBits>> algorithm,
      std::array<std::byte, KeyBits / 8> cipher_key = {},
      std::array<std::byte, BlockSizeBits / 8> initial_vector =
          GetRandomArray<BlockSizeBits / 8>(),
      std::uint32_t m_bits = 60)
      : OperationMode<BlockSizeBits, KeyBits, BufferSize>(
            std::move(algorithm), cipher_key, initial_vector),
        m(m_bits) {
    std::uint32_t counter_bytes = (m_bits + 7) / 8;
    for (int i = (BlockSizeBits / 8) - 1;
         i > (BlockSizeBits / 8) - counter_bytes; i--) {
      this->prev_vector[i] = static_cast<std::byte>(0x00);
      m_bits -= 8;
    }
    this->prev_vector[(BlockSizeBits / 8) - counter_bytes] &=
        static_cast<std::byte>(0xFF << m_bits);
    this->IV = this->prev_vector;
  }

  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::operator<<;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      const std::vector<std::byte>& data) override;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator>>(
      OperationModeOutputData<BlockSizeBits>& data) override;

 private:
  std::uint32_t m;
};

};  // namespace file_encrypt::algorithm::op_mode

// Implementation details only below here.

#include "ctr.inc"

#endif