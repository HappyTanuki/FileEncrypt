#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "algorithm/block_cipher/aes.h"
#include "cbc.h"
#include "ecb.h"

namespace file_encrypt::algorithm {

template <std::uint32_t BufferSize>
class AES128_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 128, BufferSize> {
 public:
  AES128_CBC(const std::array<std::byte, 16>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::CBC<128, 128, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<128>>(), key, iv) {}
};

template <std::uint32_t BufferSize>
class AES192_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 192, BufferSize> {
 public:
  AES192_CBC(const std::array<std::byte, 24>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::CBC<128, 192, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<192>>(), key, iv) {}
};

template <std::uint32_t BufferSize>
class AES256_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 256, BufferSize> {
 public:
  AES256_CBC(const std::array<std::byte, 32>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::CBC<128, 256, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<256>>(), key, iv) {}
};

template <std::uint32_t BufferSize>
class AES128_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 128, BufferSize> {
 public:
  AES128_ECB(const std::array<std::byte, 16>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::ECB<128, 128, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<128>>(), key, iv) {}
};

template <std::uint32_t BufferSize>
class AES192_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 192, BufferSize> {
 public:
  AES192_ECB(const std::array<std::byte, 24>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::ECB<128, 192, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<192>>(), key, iv) {}
};

template <std::uint32_t BufferSize>
class AES256_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 256, BufferSize> {
 public:
  AES256_ECB(const std::array<std::byte, 32>& key = {},
             const std::array<std::byte, 16>& iv = {})
      : file_encrypt::algorithm::op_mode::ECB<128, 256, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<256>>(), key, iv) {}
};

}  // namespace file_encrypt::algorithm

#endif