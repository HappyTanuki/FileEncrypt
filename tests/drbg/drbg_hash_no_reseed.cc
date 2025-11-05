#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "precomp.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

#define _PATH "./tests/test_vector/drbgtestvectors/drbgvectors_no_reseed/"
#define _TESTNAME "drbg_hash_sha256_no_reseed"

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

    file_encrypt::algorithm::DRBG_SHA256 drbg_sha256;
    drbg_sha256._TESTING = true;

    for (const auto& stage : algorithm_stage.stages) {
      for (const auto& step : stage.steps) {
        if (step.function_name == file_encrypt::util::NISTTestVectorParser::
                                      DRBGFunctionName::kInstantiate) {
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
          if (drbg_sha256.GetV() != step.internal_state.V ||
              drbg_sha256.GetC() != step.internal_state.C ||
              drbg_sha256.GetReseedCounter() !=
                  step.internal_state.reseed_counter) {
            std::cout << "Internal state does not match expected value."
                      << std::endl;
            std::cout << "Expected V: "
                      << file_encrypt::util::BytesToStr(step.internal_state.V)
                      << std::endl;
            std::cout << "Got V: "
                      << file_encrypt::util::BytesToStr(drbg_sha256.GetV())
                      << std::endl;
            std::cout << "Expected C: "
                      << file_encrypt::util::BytesToStr(step.internal_state.C)
                      << std::endl;
            std::cout << "Got C: "
                      << file_encrypt::util::BytesToStr(drbg_sha256.GetC())
                      << std::endl;
            std::cout << "Expected Reseed Counter: "
                      << step.internal_state.reseed_counter << std::endl;
            std::cout << "Got Reseed Counter: "
                      << drbg_sha256.GetReseedCounter() << std::endl;
            return -1;
          }
        } else if (step.function_name ==
                   file_encrypt::util::NISTTestVectorParser::DRBGFunctionName::
                       kGenerate) {
          auto generate_return_value = drbg_sha256.Generate(
              step.returned_bits.size() * 8, 256,
              step.prediction_resistance_flag, step.additional_input);
          if (generate_return_value.status !=
              file_encrypt::algorithm::CSPRNG::ReturnStatus::kSUCCESS) {
            std::cout << "Generate failed." << std::endl;
            return -1;
          }
          if (!step.returned_bits.empty() &&
              generate_return_value.pseudorandom_bits != step.returned_bits) {
            std::cout << "Generated bits do not match expected value."
                      << std::endl;
            std::cout << "Additional Input: "
                      << file_encrypt::util::BytesToStr(step.additional_input)
                      << std::endl;
            std::cout << "Expected: "
                      << file_encrypt::util::BytesToStr(step.returned_bits)
                      << std::endl;
            std::cout << "Got: "
                      << file_encrypt::util::BytesToStr(
                             generate_return_value.pseudorandom_bits)
                      << std::endl;
            return -1;
          }
        } else if (step.function_name ==
                   file_encrypt::util::NISTTestVectorParser::DRBGFunctionName::
                       kReseed) {
          drbg_sha256.Reseed(step.prediction_resistance_flag,
                             step.additional_input);
        }
      }
    }
  }

  return 0;
}