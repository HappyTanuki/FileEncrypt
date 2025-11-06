#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_HASH_DRBG_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_CSPRNG_HASH_DRBG_H_

#include <memory>

#include "algorithm/algorithm.h"
#include "csprng.h"

namespace file_encrypt::algorithm {

class HASH_DRBG : public CSPRNG {
 public:
  struct HashDFReturnValue {
    ReturnStatus status;
    std::vector<std::byte> requested_bits;
  };

  struct HashgenReturnValue {
    std::vector<std::byte> returned_bits;
  };

  HASH_DRBG(std::unique_ptr<HashAlgorithm> algorithm);

  virtual ReturnStatus InstantiateAlgorithm(
      const std::vector<std::byte>& entropy_input, std::vector<std::byte> nonce,
      const std::vector<std::byte>& personalization_string,
      const std::uint32_t& security_strangth) override final;

  virtual ReturnStatus ReseedAlgorithm(
      const std::vector<std::byte>& entropy_input,
      const std::vector<std::byte>& additional_input) override final;

  virtual GenerateReturnValue GenerateAlgorithm(
      const std::uint64_t& requested_number_of_bits,
      const std::vector<std::byte>& additional_input) override final;

  std::vector<std::byte> GetV() const { return V; }
  std::vector<std::byte> GetC() const { return C; }
  std::uint64_t GetReseedCounter() const { return reseed_counter; }

 private:
  HashDFReturnValue Hash_df(std::vector<std::byte> input_string,
                            std::uint32_t no_of_bits_to_return);
  HashgenReturnValue Hashgen(std::uint64_t requested_no_of_bits,
                             std::vector<std::byte> V);

  std::vector<std::byte> V, C;

  std::unique_ptr<HashAlgorithm> hash;

 protected:
  std::uint64_t seedlen = 0;
  std::uint64_t outlen = 0;
};

}  // namespace file_encrypt::algorithm

#endif