#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_CSPRNG_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_CSPRNG_H_
#include <array>
#include <cstdint>
#include <vector>
#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "Bcrypt.lib")
#else
#include <cstdio>
#endif

namespace file_encrypt::algorithm {

class CSPRNG {
 public:
  enum class ReturnStatus {
    kSUCCESS = 0,
    kERROR_FLAG = 1,
    kCATASTROPHIC_ERROR_FLAG = 2,
    kRESEED_REQUIRED = 3
  };

  struct GetEntropyInputReturnValue {
    ReturnStatus status;
    std::vector<std::byte> entropy_input;
  };

  struct GenerateReturnValue {
    ReturnStatus status;
    std::vector<std::byte> pseudorandom_bits;
  };
  ~CSPRNG() { Uninstantiate(); }

  constexpr ReturnStatus Instantiate(
      const std::uint32_t& requested_instantiation_security_strangth,
      const bool& prediction_resistance_flag,
      const std::vector<std::byte>& entropy_input = {},
      std::vector<std::byte> nonce = {},
      const std::vector<std::byte>& personalization_string = {});

  virtual ReturnStatus InstantiateAlgorithm(
      const std::vector<std::byte>& entropy_input, std::vector<std::byte> nonce,
      const std::vector<std::byte>& personalization_string,
      const std::uint32_t& security_strangth) = 0;

  constexpr ReturnStatus Reseed(
      const bool& prediction_resistance_request,
      const std::vector<std::byte>& additional_input,
      const std::vector<std::byte>& entropy_input = {});
  virtual ReturnStatus ReseedAlgorithm(
      const std::vector<std::byte>& entropy_input,
      const std::vector<std::byte>& additional_input) = 0;

  constexpr GenerateReturnValue Generate(
      const std::uint64_t& requested_number_of_bits,
      const std::uint32_t& requested_security_strangth,
      bool prediction_resistance_request,
      std::vector<std::byte> additional_input,
      const std::vector<std::byte>& entropy_input = {});

  virtual GenerateReturnValue GenerateAlgorithm(
      const std::uint64_t& requested_number_of_bits,
      const std::vector<std::byte>& additional_input) = 0;

  constexpr ReturnStatus Uninstantiate();

  static ReturnStatus GetRandom(char* buf, int bufsiz) {
#ifdef _WIN32
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, reinterpret_cast<UCHAR*>(buf),
                                        bufsiz,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
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

  bool _TESTING = false;

 private:
  bool valid = false;

 protected:
  GetEntropyInputReturnValue GetEntropyInput(
      const std::uint32_t& min_entropy, const std::uint32_t& min_length,
      const std::uint32_t& max_length,
      const bool& prediction_resistance_request) {
    std::vector<std::byte> random(min_length / 8);
    CSPRNG::GetRandom(reinterpret_cast<char*>(random.data()), min_length / 8);

    GetEntropyInputReturnValue result;
    result.status = ReturnStatus::kSUCCESS;
    result.entropy_input = random;

    return result;
  }

  bool support_prediction_resistance = false;
  std::uint32_t highest_supported_security_strength = 0;
  std::uint64_t max_personalization_string_length = 0;
  std::uint64_t max_additional_input_length = 0;
  std::uint64_t max_number_of_bits_per_request = 0;
  std::uint64_t reseed_interval = 0;
  std::uint64_t max_length = 0;

  bool reseed_required_flag = false;
  bool prediction_resistance_flag = false;
  std::uint32_t security_strength = 0;
  std::uint32_t reseed_counter = 0;
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