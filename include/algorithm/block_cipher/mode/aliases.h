#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "algorithm/block_cipher/aes.h"
#include "cbc.h"
#include "ctr.h"
#include "ecb.h"

namespace file_encrypt::algorithm {

// AES-CBC 모드 별칭
template <std::uint32_t KeySize, std::uint32_t BufferSize = 1>
class AES_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, KeySize, BufferSize> {
 public:
  AES_CBC(const std::array<std::byte, KeySize / 8>& key = {},
          const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CBC<128, KeySize, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}
};

// AES-ECB 모드 별칭
template <std::uint32_t KeySize, std::uint32_t BufferSize = 1>
class AES_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, KeySize, BufferSize> {
 public:
  AES_ECB(const std::array<std::byte, KeySize / 8>& key = {},
          const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::ECB<128, KeySize, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}
};

// AES-CTR 모드 별칭
template <std::uint32_t KeySize, std::uint32_t BufferSize = 1>
class AES_CTR
    : public file_encrypt::algorithm::op_mode::CTR<128, KeySize, BufferSize> {
 public:
  // IV를 명시적으로 지정하는 버전
  AES_CTR(const std::array<std::byte, KeySize / 8>& key,
          const std::array<std::byte, 16>& iv)
      : file_encrypt::algorithm::op_mode::CTR<128, KeySize, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key), iv) {}

  // 랜덤 IV 사용 버전
  explicit AES_CTR(const std::array<std::byte, KeySize / 8>& key = {})
      : file_encrypt::algorithm::op_mode::CTR<128, KeySize, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<KeySize>>(key)) {}
};

}  // namespace file_encrypt::algorithm

#endif