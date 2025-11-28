#include "csprng.h"

namespace file_encrypt::algorithm {

constexpr ReturnStatus CSPRNG::Instantiate(
    const std::uint32_t& requested_instantiation_security_strength,
    const bool& prediction_resistance_flag, std::vector<std::byte> nonce,
    const std::vector<std::byte>& personalization_string,
    const std::vector<std::byte>& entropy_input) {
  // Step 1
  if (requested_instantiation_security_strength >
      highest_supported_security_strength)
    return ReturnStatus::kERROR_FLAG;
  // Step 2
  if (prediction_resistance_flag && !support_prediction_resistance)
    return ReturnStatus::kERROR_FLAG;
  this->prediction_resistance_flag = prediction_resistance_flag;
  // Step 3
  if (personalization_string.size() * 8 > max_personalization_string_length)
    return ReturnStatus::kERROR_FLAG;
  // Step 4
  switch (requested_instantiation_security_strength) {
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
  GetEntropyInputReturnValue entropy_input_return_value;
  if (entropy_input.size() == 0 && !_TESTING) {
    entropy_input_return_value =
        GetEntropyInput(security_strength, security_strength, max_length,
                        prediction_resistance_flag);
  } else {
    entropy_input_return_value.status = ReturnStatus::kSUCCESS;
    entropy_input_return_value.entropy_input = entropy_input;
  }
  // Step 7
  if (entropy_input_return_value.status != ReturnStatus::kSUCCESS)
    return entropy_input_return_value.status;
  // Step 8
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

constexpr ReturnStatus CSPRNG::Reseed(
    const bool& prediction_resistance_request,
    const std::vector<std::byte>& additional_input,
    const std::vector<std::byte>& entropy_input) {
  // Step 1
  if (!valid) return ReturnStatus::kERROR_FLAG;
  // Step 2
  if (prediction_resistance_request && !prediction_resistance_flag)
    return ReturnStatus::kERROR_FLAG;
  // Step 3
  if (additional_input.size() * 8 > max_additional_input_length)
    return ReturnStatus::kERROR_FLAG;
  // Step 4
  GetEntropyInputReturnValue entropy_input_return_value;
  if (entropy_input.size() == 0 && !_TESTING) {
    entropy_input_return_value =
        GetEntropyInput(security_strength, security_strength, max_length,
                        prediction_resistance_flag);
  } else {
    entropy_input_return_value.status = ReturnStatus::kSUCCESS;
    entropy_input_return_value.entropy_input = entropy_input;
  }
  // Step 5
  if (entropy_input_return_value.status != ReturnStatus::kSUCCESS)
    return entropy_input_return_value.status;
  ReturnStatus status = ReseedAlgorithm(
      entropy_input_return_value.entropy_input, additional_input);
  return status;
}

constexpr CSPRNG::GenerateReturnValue CSPRNG::Generate(
    const std::uint64_t& requested_number_of_bits,
    const std::uint32_t& requested_security_strangth,
    bool prediction_resistance_request, std::vector<std::byte> additional_input,
    const std::vector<std::byte>& entropy_input) {
  // Step 1
  if (!valid) return {ReturnStatus::kERROR_FLAG, {}};
  // Step 2
  if (requested_number_of_bits > max_number_of_bits_per_request)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 3
  if (requested_security_strangth > security_strength)
    return {ReturnStatus::kERROR_FLAG, {}};
  // Step 4
  if (additional_input.size() * 8 > max_additional_input_length)
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
                                   additional_input, entropy_input);
      // Step 7.2
      if (status != ReturnStatus::kSUCCESS) return {status, {}};
      // Step 7.4
      additional_input.clear();
      // Step 7.5
      reseed_required_flag = false;
    }
    // Step 8
    generate_algorithm_return_value =
        GenerateAlgorithm(requested_number_of_bits, additional_input);
    // Step 9
    if (generate_algorithm_return_value.status ==
        ReturnStatus::kRESEED_REQUIRED) {
      // Step 9.1
      reseed_required_flag = true;
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

constexpr ReturnStatus CSPRNG::Uninstantiate() {
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

}  // namespace file_encrypt::algorithm