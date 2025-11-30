#include "algorithm_factory.h"

namespace file_encrypt::algorithm {

template <std::uint32_t DigestLen>
std::unique_ptr<HashAlgorithm<DigestLen>> HashFactory(std::string name) {}

}  // namespace file_encrypt::algorithm