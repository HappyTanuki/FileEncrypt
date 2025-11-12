#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PADDING_PKCS_7_H
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PADDING_PKCS_7_H

#include "padding.h"

namespace file_encrypt::algorithm {

// blocksize는 비트 단위임
template <std::uint32_t BlockSize>
class Pkcs_7 : public Padding<BlockSize> {
 public:
  std::vector<std::array<std::byte, BlockSize / 8>> MakePaddingBlock(
      std::vector<std::byte> data) final override;
  RemovePaddingReturnData<BlockSize> RemovePadding(
      std::vector<std::byte> data) final override;
};

};  // namespace file_encrypt::algorithm

#include "pkcs_7.inc"

#endif