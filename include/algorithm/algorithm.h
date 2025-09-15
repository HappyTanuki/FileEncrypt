#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_H_
#include <cstddef>
#include <cstdint>
#include <vector>

namespace file_encrypt::algorithm {

enum class ReturnStatusCode { kSuccess = 0, kError = -1 };

struct HashAlgorithmInputData {
  std::vector<std::byte> message = {};
  std::uint64_t bit_length = 0;
};
struct HashAlgorithmReturnData {
  std::vector<std::byte> digest = {};
  ReturnStatusCode return_code = ReturnStatusCode::kError;
};

struct CipherAlgorithmReturnData {
  std::vector<std::byte> data = {};
  ReturnStatusCode return_code = ReturnStatusCode::kError;
};

class CipherAlgorithm {
 public:
  virtual CipherAlgorithmReturnData Encrypt(
      const std::vector<std::byte>& data) const = 0;
  virtual CipherAlgorithmReturnData Decrypt(
      const std::vector<std::byte>& data) const = 0;
};

class HashAlgorithm {
 public:
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;
};
}  // namespace file_encrypt::algorithm

#endif