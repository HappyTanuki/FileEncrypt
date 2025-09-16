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
};
struct CipherAlgorithmReturnData {
  std::vector<std::byte> data = {};
};

class CipherAlgorithm {
 public:
  virtual CipherAlgorithmReturnData Encrypt(
      const CipherAlgorithmInputData& data) const = 0;
  virtual CipherAlgorithmReturnData Decrypt(
      const CipherAlgorithmInputData& data) const = 0;

  virtual void UpdateInput(const CipherAlgorithmInputData& data) = 0;
  virtual void UpdateOutput(const CipherAlgorithmInputData& data) = 0;
  virtual CipherAlgorithmReturnData Encrypt() = 0;
  virtual CipherAlgorithmReturnData Decrypt() = 0;
};

class HashAlgorithm {
 public:
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;

  virtual void Update(
      const HashAlgorithmInputData& data) = 0;
  virtual HashAlgorithmReturnData Digest() = 0;
};
}  // namespace file_encrypt::algorithm

#endif