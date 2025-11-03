#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_DRBG_SHA256_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_DRBG_SHA256_H_

#include "algorithm/sha256.h"
#include "hash_drbg.h"

namespace file_encrypt::algorithm {

class DRBG_SHA256 : public HASH_DRBG {
 public:
  DRBG_SHA256()
      : HASH_DRBG(std::make_unique<file_encrypt::algorithm::SHA256>()) {}

 protected:
  const bool support_prediction_resistance = true;
  const std::uint32_t highest_supported_security_strength = 256;
  const std::uint64_t max_personalization_string_length = 34359738368;  // 2^35
  const std::uint64_t max_additional_input_length = 34359738368;        // 2^35
  const std::uint64_t max_number_of_bits_per_request = 524288;          // 2^19
  const std::uint64_t reseed_interval = 281474976710656;                // 2^48
  const std::uint64_t max_length = 34359738368;                         // 2^35

  bool reseed_required_flag = false;
  bool prediction_resistance_flag = false;
  std::uint32_t security_strength = 256;
  std::uint64_t seedlen = 888;
  std::uint64_t outlen = 512;
};

}  // namespace file_encrypt::algorithm

#endif