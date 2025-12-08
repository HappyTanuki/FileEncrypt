#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PADDING_PADDING_H
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_PADDING_PADDING_H

#include <array>
#include <cstdint>
#include <vector>

namespace file_encrypt::algorithm {

template <std::uint32_t BlockSize>
struct RemovePaddingReturnData {
  std::array<std::byte, BlockSize / 8> data;
  size_t real_length;
};

// blocksize는 비트 단위임
template <std::uint32_t BlockSize>
class Padding {
 public:
  virtual std::vector<std::array<std::byte, BlockSize / 8>> MakePaddingBlock(
      std::span<std::byte> data) = 0;
  virtual RemovePaddingReturnData<BlockSize> RemovePadding(
      std::vector<std::byte> data) = 0;

 protected:
  std::array<std::byte, BlockSize / 8> buffer = {};
  std::uint32_t buffer_index = 0;
};

};  // namespace file_encrypt::algorithm

#endif