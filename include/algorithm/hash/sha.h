#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HASH_SHA_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HASH_SHA_H_

#include <memory>
#include <queue>

#include "algorithm/algorithm.h"

namespace file_encrypt::algorithm {

template <std::uint32_t DigestLen>
class SHA : public HashAlgorithm<DigestLen> {
 public:
  SHA();
  std::array<std::byte, DigestLen / 8> Digest(
      const HashAlgorithmInputData& data) const final override;

  void Update(const HashAlgorithmInputData& data) final override;
  std::array<std::byte, DigestLen / 8> Digest() final override;
  void Reset() final override;

 private:
  constexpr std::vector<std::array<std::uint32_t, 16>> Padding(
      const HashAlgorithmInputData& data) const;
  constexpr std::array<std::uint32_t, 16> MakeMessage(
      const std::array<std::byte, 64>& data, std::uint64_t data_bit_length);
  constexpr std::array<std::uint32_t, 8> ProcessMessageBlock(
      const std::array<std::uint32_t, 16>& M,
      const std::array<std::uint32_t, 8>& H) const;

  std::array<std::byte, 64> data_buffer;
  std::uint64_t data_buffer_bit_length = 0;
  std::uint64_t data_length = 0;

  std::array<std::uint32_t, 8> H;

  constexpr std::uint32_t ROTR(std::uint32_t x, std::uint32_t n) const;
  constexpr std::uint32_t Ch(std::uint32_t x, std::uint32_t y,
                             std::uint32_t z) const;
  constexpr std::uint32_t Maj(std::uint32_t x, std::uint32_t y,
                              std::uint32_t z) const;
  constexpr std::uint32_t Sigma0(std::uint32_t x) const;
  constexpr std::uint32_t Sigma1(std::uint32_t x) const;
  constexpr std::uint32_t sigma0(std::uint32_t x) const;
  constexpr std::uint32_t sigma1(std::uint32_t x) const;

  static constexpr std::uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  static constexpr std::uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                          0xa54ff53a, 0x510e527f, 0x9b05688c,
                                          0x1f83d9ab, 0x5be0cd19};
};
}  // namespace file_encrypt::algorithm

#include "sha.inc"

#endif
