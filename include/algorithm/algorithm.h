#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_H_
#include <cstddef>
#include <cstdint>
#include <vector>

namespace file_encrypt::algorithm {

struct HashAlgorithmInputData {
  std::vector<std::byte> message = {};
  std::uint64_t bit_length = 0;
};
struct HashAlgorithmReturnData {
  std::vector<std::byte> digest = {};
};

struct CipherAlgorithmOnetimeInputData {
  std::vector<std::byte> data = {};
  std::vector<std::byte> key = {};
};
struct CipherAlgorithmReturnData {
  std::vector<std::byte> data = {};
};

struct EncodingAlgorithmInputData {
  std::vector<std::byte> data = {};
};
struct EncodingAlgorithmReturnData {
  std::vector<std::byte> data = {};
};

template <std::uint32_t KeyBits, std::uint32_t BlockSizeBits>
class BlockCipherAlgorithm {
 public:
  BlockCipherAlgorithm() = default;
  virtual ~BlockCipherAlgorithm() = default;
  virtual CipherAlgorithmReturnData Encrypt(
      const CipherAlgorithmOnetimeInputData& data) const = 0;
  virtual CipherAlgorithmReturnData Decrypt(
      const CipherAlgorithmOnetimeInputData& data) const = 0;
  virtual CipherAlgorithmReturnData Encrypt(
      const std::array<std::byte, BlockSizeBits / 8>& data) = 0;
  virtual CipherAlgorithmReturnData Decrypt(
      const std::array<std::byte, BlockSizeBits / 8>& data) = 0;
  virtual void SetKey(const std::array<std::byte, KeyBits / 8>& cipher_key) = 0;
};

class HashAlgorithm {
 public:
  HashAlgorithm() = default;
  virtual ~HashAlgorithm() = default;
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;

  virtual void Update(const HashAlgorithmInputData& data) = 0;
  virtual HashAlgorithmReturnData Digest() = 0;
};

class EncodingAlgorithm {
 public:
  EncodingAlgorithm() = default;
  virtual ~EncodingAlgorithm() = default;
  virtual EncodingAlgorithmReturnData Encoding(
      const EncodingAlgorithmInputData& data) const = 0;
  virtual EncodingAlgorithmReturnData Decoding(
      const EncodingAlgorithmInputData& data) const = 0;
};

}  // namespace file_encrypt::algorithm

#endif