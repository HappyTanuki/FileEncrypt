#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HMAC_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HMAC_H_

#include <cstdint>
#include <memory>

#include "algorithm.h"
#include "util/helper.h"

namespace file_encrypt::algorithm {

class HMAC : public MacAlgorithm {
 public:
  HMAC(std::unique_ptr<HashAlgorithm> algorithm,
       std::vector<std::byte> key = {})
      : algorithm(std::move(algorithm)),
        inner_padding(
            std::vector<std::byte>(this->algorithm->inner_block_size / 8,
                                   static_cast<std::byte>(0x36))),
        outer_padding(
            std::vector<std::byte>(this->algorithm->inner_block_size / 8,
                                   static_cast<std::byte>(0x5C))) {
    if (key.size() > this->algorithm->inner_block_size / 8)
      key = this->algorithm->Digest({key, key.size() * 8}).digest;
    key.resize(this->algorithm->inner_block_size / 8,
               static_cast<std::byte>(0x00));
    this->key = key;
    this->xored_key = file_encrypt::util::XorVectors(key, inner_padding);
    this->digest_size = this->algorithm->digest_size;
    Reset();
  }

  void Reset() {
    algorithm->Reset();
    algorithm->Update({xored_key, xored_key.size() * 8});
  }

  // 짧거나 한 번에 처리할 필요가 있는 데이터를 처리할 때 사용.
  std::vector<std::byte> Compute(
      std::vector<std::byte> key,
      const std::vector<std::byte>& data) const final;

  // 내부적으로 버퍼링 하여 임의 길이로 계산할 때 사용.
  void Compute(const std::vector<std::byte>& data) final;
  // 내부 버퍼를 비우고 패딩하여 계산하여 반환.
  std::vector<std::byte> Finalize() final;

 private:
  std::unique_ptr<HashAlgorithm> algorithm;

  std::vector<std::byte> key;
  std::vector<std::byte> xored_key;
  const std::vector<std::byte> inner_padding;
  const std::vector<std::byte> outer_padding;
};

}  // namespace file_encrypt::algorithm

#endif