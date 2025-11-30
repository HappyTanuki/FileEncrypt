#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_TRAITS_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_TRAITS_H_

#include <unordered_map>

#include "block_cipher/mode/aliases.h"
#include "hash/sha.h"

namespace file_encrypt::algorithm {

template <std::uint32_t KeyBits>
constexpr const char* AESAlgorithmName();

template <>
constexpr const char* AESAlgorithmName<128>() {
  return "AES-128";
}

template <>
constexpr const char* AESAlgorithmName<192>() {
  return "AES-192";
}

template <>
constexpr const char* AESAlgorithmName<256>() {
  return "AES-256";
}

template <typename T>
struct AlgorithmTraits;

template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES<KeyBits>> {
  static constexpr const std::string name = AESAlgorithmName<KeyBits>();
  static constexpr const std::uint32_t bits = KeyBits;
};

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::CBC<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "CBC";
  static constexpr const std::uint32_t bits = KeyBits;
};
template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::ECB<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "ECB";
  static constexpr const std::uint32_t bits = KeyBits;
};
template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::CTR<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "CTR";
  static constexpr const std::uint32_t bits = KeyBits;
};

template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_CBC<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::CBC<128, KeyBits, 1>>::name;
  static constexpr const std::uint32_t bits = KeyBits;
};
template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_ECB<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::ECB<128, KeyBits, 1>>::name;
  static constexpr const std::uint32_t bits = KeyBits;
};
template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_CTR<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::CTR<128, KeyBits, 1>>::name;
  static constexpr const std::uint32_t bits = KeyBits;
};

template <>
struct AlgorithmTraits<SHA<1>> {
  static constexpr const std::string name = "SHA-1";
  static constexpr const std::uint32_t bits = 160;
};

template <>
struct AlgorithmTraits<SHA<224>> {
  static constexpr const std::string name = "SHA-224";
  static constexpr const std::uint32_t bits = 224;
};

template <>
struct AlgorithmTraits<SHA<256>> {
  static constexpr const std::string name = "SHA-256";
  static constexpr const std::uint32_t bits = 256;
};

#define REGISTER_AES_VARIANTS(bits)                   \
  {AlgorithmTraits<AES_CBC<bits>>::name, bits},       \
      {AlgorithmTraits<AES_ECB<bits>>::name, bits}, { \
    AlgorithmTraits<AES_CTR<bits>>::name, bits        \
  }

static const std::unordered_map<std::string, int> kAlgoBits = {
    REGISTER_AES_VARIANTS(128),
    REGISTER_AES_VARIANTS(192),
    REGISTER_AES_VARIANTS(256),
    {AlgorithmTraits<SHA<1>>::name, AlgorithmTraits<SHA<1>>::bits},
    {AlgorithmTraits<SHA<224>>::name, AlgorithmTraits<SHA<224>>::bits},
    {AlgorithmTraits<SHA<256>>::name, AlgorithmTraits<SHA<256>>::bits}};

}  // namespace file_encrypt::algorithm

#endif