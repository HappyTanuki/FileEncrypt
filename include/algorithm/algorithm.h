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
  std::string algorithm_name = "";
};

// 해시 알고리즘의 기본 인터페이스
class HashAlgorithm {
 public:
  HashAlgorithm() = default;
  virtual ~HashAlgorithm() = default;
  // 짧거나 한 번에 처리할 필요가 있는 데이터를 처리할 때 사용. 내부 상태를
  // 업데이트하거나 내부 상태에 이어서 해시를 계산하지 않음.
  virtual HashAlgorithmReturnData Digest(
      const HashAlgorithmInputData& data) const = 0;

  // 내부적으로 버퍼링 하여 임의 길이로 해시를 계산할 때 사용.
  virtual void Update(const HashAlgorithmInputData& data) = 0;
  // 내부 버퍼를 비우고 패딩하여 해시를 계산하여 반환하고 내부 상태를 초기화함.
  virtual HashAlgorithmReturnData Digest() = 0;
  // 인스턴스 리셋
  virtual void Reset() = 0;

  // HMAC에서 필요해서 추가함. 이 해시 알고리즘이 한번에 처리하는 블록 크기,
  // 비트 단위로 표시(예: SHA256은 512비트임).
  std::uint32_t inner_block_size = 0;
};

// MAC 알고리즘의 기본 인터페이스
class MacAlgorithm {
 public:
  MacAlgorithm() = default;
  virtual ~MacAlgorithm() = default;
  // 짧거나 한 번에 처리할 필요가 있는 데이터를 처리할 때 사용.
  virtual std::vector<std::byte> Compute(
      std::vector<std::byte> key, const std::vector<std::byte>& data) const = 0;

  // 내부적으로 버퍼링 하여 임의 길이로 계산할 때 사용.
  virtual void Compute(const std::vector<std::byte>& data) = 0;
  // 내부 버퍼를 비우고 패딩하여 계산하여 반환.
  virtual std::vector<std::byte> Finalize() = 0;
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