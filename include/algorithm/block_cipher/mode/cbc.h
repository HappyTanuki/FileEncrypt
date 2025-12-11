#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_CBC_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_CBC_H_

#include <span>

#include "operation.h"

namespace file_encrypt::algorithm::op_mode {

// CBC 운영 모드, 데이터를 버퍼링하였다가 블록 단위로 처리함
template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
class CBC : public OperationMode<BlockSizeBits, KeyBits, BufferSize> {
 public:
  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::OperationMode;

  using OperationMode<BlockSizeBits, KeyBits, BufferSize>::operator<<;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      const std::span<const std::byte> data) override;
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator<<(
      const std::array<std::byte, BlockSizeBits / 8>& data);
  constexpr OperationMode<BlockSizeBits, KeyBits, BufferSize>& operator>>(
      OperationModeOutputData<BlockSizeBits>& data) override;
};

};  // namespace file_encrypt::algorithm::op_mode

// Implementation details only below here.

#include "cbc.inc"

#endif