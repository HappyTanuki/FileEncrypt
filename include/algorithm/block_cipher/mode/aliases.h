#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "algorithm/block_cipher/aes.h"
#include "cbc.h"
#include "ctr.h"
#include "ecb.h"

namespace file_encrypt::algorithm {

// AES 모드 별 별칭
template <std::uint32_t KeySize>
class AES_CBC : public file_encrypt::algorithm::op_mode::CBC<128, KeySize, 1> {
 public:
  AES_CBC(const std::array<std::byte, KeySize / 8>& key = {},
          const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CBC<128, KeySize, 1>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}
};

// AES 모드 별 별칭
template <std::uint32_t KeySize>
class AES_ECB : public file_encrypt::algorithm::op_mode::ECB<128, KeySize, 1> {
 public:
  AES_ECB(const std::array<std::byte, KeySize / 8>& key = {},
          const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::ECB<128, KeySize, 1>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}
};

// AES 모드 별 별칭
template <std::uint32_t KeySize>
class AES_CTR : public file_encrypt::algorithm::op_mode::CTR<128, KeySize, 1> {
 public:
  AES_CTR(const std::array<std::byte, KeySize / 8>& key = {},
          const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CTR<128, KeySize, 1>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}
};

}  // namespace file_encrypt::algorithm

#endif