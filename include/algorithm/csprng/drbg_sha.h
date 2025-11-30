#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_DRBG_SHA_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_DRBG_SHA_H_

#include <limits>

#include "algorithm/hash/sha.h"
#include "hash_drbg.h"

namespace file_encrypt::algorithm {

template <std::uint32_t HashDigestLen>
class DRBG_SHA : public HASH_DRBG<HashDigestLen> {
 public:
  DRBG_SHA();
};

}  // namespace file_encrypt::algorithm

#include "drbg_sha.inc"

#endif