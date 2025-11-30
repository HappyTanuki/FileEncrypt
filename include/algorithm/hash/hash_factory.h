#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HASH_HASH_FACTORY_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_HASH_HASH_FACTORY_H_

#include <memory>

#include "algorithm/algorithm.h"

namespace file_encrypt::algorithm {

template <std::uint32_t DigestLen>
std::unique_ptr<HashAlgorithm<DigestLen>> HashFactory(std::string name);
}

#endif