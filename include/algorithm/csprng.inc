#include "csprng.h"

#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "Bcrypt.lib")
#else
#include <cstdio>
#endif

namespace file_encrypt::algorithm {

constexpr CSPRNG::ReturnStatus CSPRNG::Instantiate(
    std::uint32_t requested_instantiation_security_strangth,
    bool prediction_resistance_flag,
    std::vector<std::byte> personalization_string,
    std::uint64_t personalization_string_length) {
  // Step 1
  if (requested_instantiation_security_strangth >
      highest_supported_security_strength)
    return ReturnStatus::kERROR_FLAG;
  // Step 2
  if (prediction_resistance_flag && !support_prediction_resistance)
    return ReturnStatus::kERROR_FLAG;
  this->prediction_resistance_flag = prediction_resistance_flag;
  // Step 3
  if (personalization_string_length > max_personalization_string_length)
    return ReturnStatus::kERROR_FLAG;
  // Step 4
  switch (requested_instantiation_security_strangth) {
    default:
    case 256:
      security_strength = 256;
      break;
    case 192:
      security_strength = 192;
      break;
    case 128:
      security_strength = 128;
      break;
    case 112:
      security_strength = 112;
      break;
  }
  // Step 5
  // Step 6
  GetEntropyInputReturnValue entropy_input_return_value =
      GetEntropyInput(security_strength, security_strength, security_strength,
                      prediction_resistance_flag);
  // Step 7
  if (entropy_input_return_value.status != ReturnStatus::kSUCCESS)
    return entropy_input_return_value.status;
  // Step 8
  std::vector<std::byte> nonce;
  nonce.reserve((security_strength + 1) / 2);
  ReturnStatus rng_status =
      GetRandom(reinterpret_cast<char*>(nonce.data()), nonce.size());
  if (rng_status != ReturnStatus::kSUCCESS) return rng_status;
  // Step 9-12
  ReturnStatus status =
      InstantiateAlgorithm(entropy_input_return_value.entropy_input, nonce,
                           personalization_string, security_strength);
  if (status != ReturnStatus::kSUCCESS) {
    return status;
  }
  valid = true;

  return ReturnStatus::kSUCCESS;
}

constexpr CSPRNG::ReturnStatus CSPRNG::Reseed(
    bool prediction_resistance_request, std::vector<std::byte> additional_input,
    std::uint64_t additional_input_length) {
  // Step 1
  if (!valid) return ReturnStatus::kERROR_FLAG;
  // Step 2
  if (prediction_resistance_request && !prediction_resistance_flag)
    return ReturnStatus::kERROR_FLAG;
  // Step 3
  if (additional_input_length > max_additional_input_length)
    return ReturnStatus::kERROR_FLAG;
  // Step 4
  GetEntropyInputReturnValue entropy_input_return_value =
      GetEntropyInput(security_strength, security_strength, security_strength,
                      prediction_resistance_flag);
  // Step 5
  if (entropy_input_return_value.status != ReturnStatus::kSUCCESS)
    return entropy_input_return_value.status;
  ReturnStatus status =
      ReseedAlgorithm(additional_input, additional_input_length);
  return status;
}

CSPRNG::ReturnStatus CSPRNG::GetRandom(char* buf, int bufsiz) {
#ifdef _WIN32
  if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, reinterpret_cast<UCHAR*>(buf),
                                      bufsiz, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    return ReturnStatus::kERROR_FLAG;
  return ReturnStatus::kSUCCESS;
#else
  static std::FILE* urandom = fopen("/dev/urandom", "rb");
  if (!urandom) return ReturnStatus::kCATASTROPHIC_ERROR_FLAG;
  size_t n = std::fread(buf, 1, bufsiz, urandom);
  if (n != (size_t)bufsiz) return ReturnStatus::kERROR_FLAG;
  return ReturnStatus::kSUCCESS;
#endif
}

}  // namespace file_encrypt::algorithm