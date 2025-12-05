#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ECB_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ECB_H_

#include "operation.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class ECB : public OperationMode<BlockSizeBits, KeyBits, BufferSize> {
 public:
  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::OperationMode;

  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::operator<<;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      std::span<const std::byte> data) override;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator>>(
      OperationModeOutputData<BlockSizeBits>& data) override;
};

};  // namespace file_encrypt::algorithm::op_mode

// Implementation details only below here.

#include "ecb.inc"

#endif