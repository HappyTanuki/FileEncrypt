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

// 블록 암호 알고리즘의 기본 인터페이스
template <std::uint32_t KeyBits, std::uint32_t BlockSizeBits>
class BlockCipherAlgorithm {
 public:
  BlockCipherAlgorithm() = default;
  virtual ~BlockCipherAlgorithm() = default;
  // 키를 내부에 유지하지 않는 단발성 암호화에 사용.
  virtual CipherAlgorithmReturnData Encrypt(
      const CipherAlgorithmOnetimeInputData& data) const = 0;
  // 키를 내부에 유지하지 않는 단발성 복호화에 사용.
  virtual CipherAlgorithmReturnData Decrypt(
      const CipherAlgorithmOnetimeInputData& data) const = 0;
  // 키를 내부에 유지하는 암호화에 사용.
  virtual CipherAlgorithmReturnData Encrypt(
      const std::array<std::byte, BlockSizeBits / 8>& data) = 0;
  // 키를 내부에 유지하는 복호화에 사용.
  virtual CipherAlgorithmReturnData Decrypt(
      const std::array<std::byte, BlockSizeBits / 8>& data) = 0;
  // 내부에 키를 설정.
  virtual void SetKey(const std::array<std::byte, KeyBits / 8>& cipher_key) = 0;
  std::string algorithm_name = "";
};

// 해쉬 알고리즘의 기본 인터페이스
class HashAlgorithm {
 public:
  HashAlgorithm() = default;
  virtual ~HashAlgorithm() = default;
  // 짧거나 한 번에 처리할 필요가 있는 데이터를 처리할 때 사용.
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;

  // 내부적으로 버퍼링 하여 임의 길이로 해쉬를 계산할 때 사용.
  virtual void Update(const HashAlgorithmInputData& data) = 0;
  // 내부 버퍼를 비우고 패딩하여 해쉬를 계산하여 반환.
  virtual HashAlgorithmReturnData Digest() = 0;
};

// 인코딩 알고리즘의 기본 인터페이스
class EncodingAlgorithm {
 public:
  EncodingAlgorithm() = default;
  virtual ~EncodingAlgorithm() = default;
  virtual std::vector<std::byte> Encoding(
      const std::vector<std::byte>& data) const = 0;
  virtual std::vector<std::byte> Decoding(
      const std::vector<std::byte>& data) const = 0;
};

}  // namespace file_encrypt::algorithm

#endif