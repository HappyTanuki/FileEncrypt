#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_H_
#include <array>
#include <cstdint>
#include <vector>

namespace file_encrypt::algorithm {

class CSPRNG {
 public:
  enum class ReturnStatus {
    kSUCCESS = 0,
    kERROR_FLAG = 1,
    kCATASTROPHIC_ERROR_FLAG = 2
  };

  struct GetEntropyInputReturnValue {
    ReturnStatus status;
    std::vector<std::byte> entropy_input;
  };

  constexpr ReturnStatus Instantiate(
      std::uint32_t requested_instantiation_security_strangth,
      bool prediction_resistance_flag,
      std::vector<std::byte> personalization_string,
      std::uint64_t personalization_string_length);

  virtual ReturnStatus InstantiateAlgorithm(
      std::vector<std::byte> entropy_input, std::vector<std::byte> nonce,
      std::vector<std::byte> personalization_string,
      std::uint32_t security_strangth) = 0;

  constexpr ReturnStatus Reseed(bool prediction_resistance_request,
                                std::vector<std::byte> additional_input,
                                std::uint64_t additional_input_length);
  virtual ReturnStatus ReseedAlgorithm(
      std::vector<std::byte> additional_input,
      std::uint64_t additional_input_length) = 0;

  static ReturnStatus GetRandom(char* buf, int bufsiz);

 private:
  bool valid = false;
  std::uint32_t security_strength = 256;

 protected:
  GetEntropyInputReturnValue GetEntropyInput(
      std::uint32_t min_entropy, std::uint32_t min_length,
      std::uint32_t max_length, bool prediction_resistance_request);

  const bool support_prediction_resistance = true;
  bool prediction_resistance_flag = false;
  const std::uint32_t highest_supported_security_strength = 256;
  const std::uint64_t max_personalization_string_length = 34359738368;  // 2^35
  const std::uint64_t max_additional_input_length = 34359738368;        // 2^35
};

template <std::uint32_t Size>
std::array<std::byte, Size> GetRandomArray() {
  std::array<std::byte, Size> random = {};
  CSPRNG::GetRandom(reinterpret_cast<char*>(random.data()), Size);
  return random;
}
}  // namespace file_encrypt::algorithm

// Implementation details only below here.
#include "csprng.inc"

#endif