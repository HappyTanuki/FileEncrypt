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

struct CipherAlgorithmInputData {
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

class BlockCipherAlgorithm {
 public:
  BlockCipherAlgorithm() = default;
  ~BlockCipherAlgorithm() = default;
  virtual CipherAlgorithmReturnData Encrypt(
      const CipherAlgorithmInputData& data) const = 0;
  virtual CipherAlgorithmReturnData Decrypt(
      const CipherAlgorithmInputData& data) const = 0;
};

class HashAlgorithm {
 public:
  HashAlgorithm() = default;
  ~HashAlgorithm() = default;
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;

  virtual void Update(const HashAlgorithmInputData& data) = 0;
  virtual HashAlgorithmReturnData Digest() = 0;
};

class EncodingAlgorithm {
 public:
  EncodingAlgorithm() = default;
  ~EncodingAlgorithm() = default;
  virtual EncodingAlgorithmReturnData Encoding(
      const EncodingAlgorithmInputData& data) const = 0;
  virtual EncodingAlgorithmReturnData Decoding(
      const EncodingAlgorithmInputData& data) const = 0;
};

}  // namespace file_encrypt::algorithm

#endif