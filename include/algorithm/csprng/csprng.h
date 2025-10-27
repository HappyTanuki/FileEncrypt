#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_CSPRNG_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_CSPRNG_H_
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

  struct GenerateReturnValue {
    ReturnStatus status;
    std::vector<std::byte> pseudorandom_bits;
  };

  constexpr ReturnStatus Instantiate(
      const std::uint32_t& requested_instantiation_security_strangth,
      const bool& prediction_resistance_flag,
      const std::vector<std::byte>& personalization_string,
      const std::uint64_t& personalization_string_length);

  virtual ReturnStatus InstantiateAlgorithm(
      const std::vector<std::byte>& entropy_input, std::vector<std::byte> nonce,
      const std::vector<std::byte>& personalization_string,
      const std::uint32_t& security_strangth) = 0;

  constexpr ReturnStatus Reseed(const bool& prediction_resistance_request,
                                const std::vector<std::byte>& additional_input,
                                const std::uint64_t& additional_input_length);
  virtual ReturnStatus ReseedAlgorithm(
      const std::vector<std::byte>& additional_input,
      const std::uint64_t& additional_input_length) = 0;

  constexpr GenerateReturnValue Generate(
      const std::uint64_t& requested_number_of_bits,
      const std::uint32_t& requested_security_strangth,
      bool prediction_resistance_request,
      const std::vector<std::byte>& additional_input,
      const std::uint64_t& additional_input_length);

  virtual GenerateReturnValue GenerateAlgorithm(
      const std::uint64_t& requested_number_of_bits,
      const std::vector<std::byte>& additional_input,
      const std::uint64_t& additional_input_length) = 0;

  constexpr ReturnStatus Uninstantiate();

  static ReturnStatus GetRandom(char* buf, int bufsiz);

 private:
  bool valid = false;

 protected:
  GetEntropyInputReturnValue GetEntropyInput(
      const std::uint32_t& min_entropy, const std::uint32_t& min_length,
      const std::uint32_t& max_length,
      const bool& prediction_resistance_request);

  const bool support_prediction_resistance = true;
  const std::uint32_t highest_supported_security_strength = 256;
  const std::uint64_t max_personalization_string_length = 34359738368;  // 2^35
  const std::uint64_t max_additional_input_length = 34359738368;        // 2^35
  const std::uint64_t max_number_of_bits_per_request = 34359738368;     // 2^35
  const std::uint64_t reseed_interval = 1024;  // depends on algorithm

  bool reseed_required_flag = false;
  bool prediction_resistance_flag = false;
  std::uint32_t security_strength = 256;
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