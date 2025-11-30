#include "algorithm/algorithm_traits.h"
#include "algorithm_factory.h"
#include "algorithm/block_cipher/mode/aliases.h"

namespace file_encrypt::algorithm::op_mode {

template <std::uint32_t KeyBits>
std::unique_ptr<OperationMode<128, KeyBits, 1>> OPModeFactory(
    std::string name, const std::array<std::byte, KeyBits / 8>& key,
    const std::array<std::byte, 16>& iv) {
  if (name == file_encrypt::algorithm::AlgorithmTraits<
                  file_encrypt::algorithm::AES_CBC<KeyBits>>::name) {
    return std::make_unique<file_encrypt::algorithm::AES_CBC<KeyBits>>(key, iv);
  } else if (name == file_encrypt::algorithm::AlgorithmTraits<
                         file_encrypt::algorithm::AES_ECB<KeyBits>>::name) {
    return std::make_unique<file_encrypt::algorithm::AES_ECB<KeyBits>>(key, iv);
  } else if (name == file_encrypt::algorithm::AlgorithmTraits<
                         file_encrypt::algorithm::AES_CTR<KeyBits>>::name) {
    return std::make_unique<file_encrypt::algorithm::AES_CTR<KeyBits>>(key, iv);
  } else {
    return std::make_unique<file_encrypt::algorithm::AES_CBC<KeyBits>>(key, iv);
  }
}

}  // namespace file_encrypt::algorithm::op_mode