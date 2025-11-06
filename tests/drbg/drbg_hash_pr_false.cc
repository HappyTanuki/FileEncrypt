#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "precomp.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

#define _PATH "./tests/test_vector/drbgtestvectors/drbgvectors_pr_false/"
#define _TESTNAME "drbg_hash_sha256_pr_false"

int CheckCondition(
    const file_encrypt::util::NISTTestVectorParser::NISTTestDRBGHashStep& step,
    const file_encrypt::algorithm::DRBG_SHA256& drbg,
    const std::vector<std::byte>& generated_pseudorandom_bits = {}) {
  if (drbg.GetV() != step.internal_state.V ||
      drbg.GetC() != step.internal_state.C ||
      drbg.GetReseedCounter() != step.internal_state.reseed_counter) {
    std::cout << "Internal state does not match expected value." << std::endl;
    std::cout << "Expected V: "
              << file_encrypt::util::BytesToStr(step.internal_state.V)
              << std::endl;
    std::cout << "Got V: " << file_encrypt::util::BytesToStr(drbg.GetV())
              << std::endl;
    std::cout << "Expected C: "
              << file_encrypt::util::BytesToStr(step.internal_state.C)
              << std::endl;
    std::cout << "Got C: " << file_encrypt::util::BytesToStr(drbg.GetC())
              << std::endl;
    std::cout << "Expected Reseed Counter: "
              << step.internal_state.reseed_counter << std::endl;
    std::cout << "Got Reseed Counter: " << drbg.GetReseedCounter() << std::endl;
    return -1;
  }
  if (!step.returned_bits.empty() && !generated_pseudorandom_bits.empty() &&
      generated_pseudorandom_bits != step.returned_bits) {
    std::cout << "Generated bits do not match expected value." << std::endl;
    std::cout << "Additional Input: "
              << file_encrypt::util::BytesToStr(step.additional_input)
              << std::endl;
    std::cout << "Expected: "
              << file_encrypt::util::BytesToStr(step.returned_bits)
              << std::endl;
    std::cout << "Got: "
              << file_encrypt::util::BytesToStr(generated_pseudorandom_bits)
              << std::endl;
    return -1;
  }
  return 0;
}

int main() {
  std::vector<
      file_encrypt::util::NISTTestVectorParser::NISTTestDRBGHashAlgorithm>
      test_vectors;
  if (file_encrypt::util::NISTTestVectorParser::ParseHashDRBGVector(
          _PATH "Hash_DRBG.txt", test_vectors) !=
      file_encrypt::util::NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string = test_vectors.back().hash_algorithm_name;
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << "Performing " _TESTNAME " test: " << std::endl;
  for (const auto& algorithm_stage : test_vectors) {
    if (algorithm_stage.hash_algorithm_name != "SHA-256") continue;

    for (const auto& stage : algorithm_stage.stages) {
      file_encrypt::algorithm::DRBG_SHA256 drbg_sha256;
      drbg_sha256._TESTING = true;

      for (const auto& step : stage.steps) {
        if (step.function_name == file_encrypt::util::NISTTestVectorParser::
                                      DRBGFunctionName::kInstantiate) {
          std::cout << "Instantiate Step:" << std::endl;
          std::cout << "Entropy Input: "
                    << file_encrypt::util::BytesToStr(step.entropy_input)
                    << std::endl;
          std::cout << "Nonce: " << file_encrypt::util::BytesToStr(step.nonce)
                    << std::endl;
          std::cout << "Personalization String: "
                    << file_encrypt::util::BytesToStr(
                           step.personalization_string)
                    << std::endl;
          std::cout << "Prediction Resistance Flag: "
                    << (step.prediction_resistance_flag ? "true" : "false")
                    << std::endl;
          drbg_sha256.Instantiate(256, step.prediction_resistance_flag,
                                  step.entropy_input, step.nonce,
                                  step.personalization_string);
          if (CheckCondition(step, drbg_sha256) != 0) return -1;
        } else if (step.function_name ==
                   file_encrypt::util::NISTTestVectorParser::DRBGFunctionName::
                       kGenerate) {
          std::cout << "Generate Step:" << std::endl;
          std::cout << "Additional Input: "
                    << file_encrypt::util::BytesToStr(step.additional_input)
                    << std::endl;
          std::cout << "Entropy Input: "
                    << file_encrypt::util::BytesToStr(step.entropy_input)
                    << std::endl;
          auto generate_return_value = drbg_sha256.Generate(
              stage.ReturnedBitsLen, 256, step.prediction_resistance_flag,
              step.additional_input, step.entropy_input);
          if (generate_return_value.status !=
              file_encrypt::algorithm::CSPRNG::ReturnStatus::kSUCCESS) {
            std::cout << "Generate failed." << std::endl;
            return -1;
          }
          if (CheckCondition(step, drbg_sha256,
                             generate_return_value.pseudorandom_bits) != 0)
            return -1;
        } else if (step.function_name ==
                   file_encrypt::util::NISTTestVectorParser::DRBGFunctionName::
                       kReseed) {
          std::cout << "Reseed Step:" << std::endl;
          drbg_sha256.Reseed(step.prediction_resistance_flag,
                             step.additional_input, step.entropy_input);
          if (CheckCondition(step, drbg_sha256) != 0) return -1;
        }
      }
    }
  }

  return 0;
}