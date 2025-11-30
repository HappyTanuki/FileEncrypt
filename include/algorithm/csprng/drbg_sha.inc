#include "algorithm/csprng/drbg_sha.h"

namespace file_encrypt::algorithm {

template <>
DRBG_SHA<256>::DRBG_SHA()
    : HASH_DRBG<256>(std::make_unique<file_encrypt::algorithm::SHA<256>>()) {
  support_prediction_resistance = true;
  highest_supported_security_strength = 256;
  max_personalization_string_length = 34359738368;  // 2^35
  max_additional_input_length = 34359738368;        // 2^35
  max_number_of_bits_per_request = 524288;          // 2^19
  reseed_interval = (std::numeric_limits<
      std::uint32_t>::max)();  // 실제 최대값은 2^48이지만 이 값과 비교하여야
                              // 하는 변수가 uint32_t이기 때문에 최대값으로 설정
  max_length = 34359738368;   // 2^35

  reseed_required_flag = false;
  prediction_resistance_flag = false;
  security_strength = 256;
  seedlen = 440;
  outlen = 256;
}

}  // namespace file_encrypt::algorithm