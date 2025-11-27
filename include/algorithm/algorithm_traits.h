#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_TRAITS_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_ALGORITHM_TRAITS_H_

#include "block_cipher/mode/aliases.h"

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
};

template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::CBC<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "CBC";
};
template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::ECB<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "ECB";
};
template <std::uint32_t BlockSizeBits, std::uint32_t KeyBits,
          std::uint32_t BufferSize>
struct AlgorithmTraits<
    file_encrypt::algorithm::op_mode::CTR<BlockSizeBits, KeyBits, BufferSize>> {
  static constexpr const std::string name = "CTR";
};

template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_CBC<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::CBC<128, KeyBits, 1>>::name;
};
template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_ECB<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::ECB<128, KeyBits, 1>>::name;
};
template <std::uint32_t KeyBits>
struct AlgorithmTraits<AES_CTR<KeyBits>> {
  static constexpr const std::string name =
      std::string(AESAlgorithmName<KeyBits>()) + "-" +
      file_encrypt::algorithm::AlgorithmTraits<
          file_encrypt::algorithm::op_mode::CTR<128, KeyBits, 1>>::name;
};

}  // namespace file_encrypt::algorithm

#endif