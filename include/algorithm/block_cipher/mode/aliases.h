#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "algorithm/block_cipher/aes.h"
#include "cbc.h"
#include "ctr.h"
#include "ecb.h"

namespace file_encrypt::algorithm {

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_128_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 128, BufferSize> {
 public:
  AES_128_CBC(const std::array<std::byte, 16>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CBC<128, 128, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<128>>(), key, iv) {
    this->SetAlgorithmName("CBC");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_192_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 192, BufferSize> {
 public:
  AES_192_CBC(const std::array<std::byte, 24>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CBC<128, 192, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<192>>(), key, iv) {
    this->SetAlgorithmName("CBC");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_256_CBC
    : public file_encrypt::algorithm::op_mode::CBC<128, 256, BufferSize> {
 public:
  AES_256_CBC(const std::array<std::byte, 32>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CBC<128, 256, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<256>>(), key, iv) {
    this->SetAlgorithmName("CBC");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_128_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 128, BufferSize> {
 public:
  AES_128_ECB(const std::array<std::byte, 16>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::ECB<128, 128, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<128>>(), key, iv) {
    this->SetAlgorithmName("ECB");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_192_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 192, BufferSize> {
 public:
  AES_192_ECB(const std::array<std::byte, 24>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::ECB<128, 192, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<192>>(), key, iv) {
    this->SetAlgorithmName("ECB");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_256_ECB
    : public file_encrypt::algorithm::op_mode::ECB<128, 256, BufferSize> {
 public:
  AES_256_ECB(const std::array<std::byte, 32>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::ECB<128, 256, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<256>>(), key, iv) {
    this->SetAlgorithmName("ECB");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_128_CTR
    : public file_encrypt::algorithm::op_mode::CTR<128, 128, BufferSize> {
 public:
  AES_128_CTR(const std::array<std::byte, 16>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CTR<128, 128, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<128>>(), key, iv) {
    this->SetAlgorithmName("CTR");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_192_CTR
    : public file_encrypt::algorithm::op_mode::CTR<128, 192, BufferSize> {
 public:
  AES_192_CTR(const std::array<std::byte, 24>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CTR<128, 192, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<192>>(), key, iv) {
    this->SetAlgorithmName("CTR");
  }
};

// AES 모드 별 별칭 클래스 텔플릿은 내부적으로 유지할 블록 갯수
template <std::uint32_t BufferSize>
class AES_256_CTR
    : public file_encrypt::algorithm::op_mode::CTR<128, 256, BufferSize> {
 public:
  AES_256_CTR(const std::array<std::byte, 32>& key = {},
              const std::array<std::byte, 16>& iv = GetRandomArray<16>())
      : file_encrypt::algorithm::op_mode::CTR<128, 256, BufferSize>(
            std::make_unique<file_encrypt::algorithm::AES<256>>(), key, iv) {
    this->SetAlgorithmName("CTR");
  }
};

}  // namespace file_encrypt::algorithm

#endif