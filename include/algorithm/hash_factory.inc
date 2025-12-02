#include "algorithm_factory.h"
#include "algorithm_traits.h"

namespace file_encrypt::algorithm {

template <std::uint32_t DigestLen>
std::unique_ptr<HashAlgorithm<DigestLen>> HashFactory(std::string name) {
  if (name == file_encrypt::algorithm::AlgorithmTraits<
                  file_encrypt::algorithm::SHA<DigestLen>>::name) {
    return std::make_unique<file_encrypt::algorithm::SHA<DigestLen>>();
  } else {
    return std::make_unique<file_encrypt::algorithm::SHA<DigestLen>>();
  }
}

}  // namespace file_encrypt::algorithm