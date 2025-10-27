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

constexpr CSPRNG::GenerateReturnValue CSPRNG::Generate(
    std::uint64_t requested_number_of_bits,
    std::uint32_t requested_security_strangth,
    bool prediction_resistance_request, std::vector<std::byte> additional_input,
    std::uint64_t additional_input_length) {
  // Step 1
  if (!valid) return {ReturnStatus::kERROR_FLAG, {}};
  // Step 2
  if (requested_number_of_bits > max_number_of_bits_per_request)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 3
  if (requested_security_strangth > security_strength)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 4
  if (additional_input_length > max_additional_input_length)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 5
  if (prediction_resistance_request && !prediction_resistance_flag)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 6
  reseed_required_flag = false;

  GenerateReturnValue generate_algorithm_return_value;
  while (true) {
    // Step 7
    if (reseed_required_flag || prediction_resistance_request) {
      // Step 7.1
      ReturnStatus status = Reseed(prediction_resistance_request,
                                   additional_input, additional_input_length);
      // Step 7.2
      if (status != ReturnStatus::kSUCCESS) return {status, {}};
      // Step 7.4
      additional_input.clear();
      // Step 7.5
      reseed_required_flag = false;
    }
    // Step 8
    generate_algorithm_return_value = GenerateAlgorithm(
        requested_number_of_bits, additional_input, additional_input_length);
    // Step 9
    if (reseed_required_flag) {
      // Step 9.1
      // Step 9.2
      if (prediction_resistance_flag) prediction_resistance_request = true;
      // Step 9.3
      continue;
    }
    break;
  }
  // Step 11
  return {ReturnStatus::kSUCCESS,
          generate_algorithm_return_value.pseudorandom_bits};
}

constexpr CSPRNG::ReturnStatus CSPRNG::Uninstantiate() {
  // Step 1
  if (!valid) return ReturnStatus::kERROR_FLAG;
  // Step 2
  valid = false;
  security_strength = 256;
  prediction_resistance_flag = false;

  reseed_required_flag = false;
  // Step 3
  return ReturnStatus::kSUCCESS;
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