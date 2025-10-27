#include "algorithm/csprng/hash_drbg.h"

#include <cstring>

namespace file_encrypt::algorithm {

HASH_DRBG::ReturnStatus HASH_DRBG::InstantiateAlgorithm(
    const std::vector<std::byte>& entropy_input, std::vector<std::byte> nonce,
    const std::vector<std::byte>& personalization_string,
    const std::uint32_t& security_strangth) {
  std::vector<std::byte> seed_material(entropy_input.size() + nonce.size() +
                                       personalization_string.size());
  std::uint64_t offset = 0;
  HashDFReturnValue hash_df_return_value;

  std::memcpy(seed_material.data() + offset, entropy_input.data(),
              entropy_input.size());
  offset += entropy_input.size();
  std::memcpy(seed_material.data() + offset, nonce.data(), nonce.size());
  offset += nonce.size();
  std::memcpy(seed_material.data() + offset, personalization_string.data(),
              personalization_string.size());

  hash_df_return_value = Hash_df(seed_material, seedlen);
  if (hash_df_return_value.status != ReturnStatus::kSUCCESS)
    return hash_df_return_value.status;
  V = hash_df_return_value.requested_bits;

  // using C as temporal variable
  C.resize(V.size() + 1);
  C[0] = (std::byte)0x00;
  std::memcpy(C.data() + 1, V.data(), V.size());
  hash_df_return_value = Hash_df(C, seedlen);
  if (hash_df_return_value.status != ReturnStatus::kSUCCESS)
    return hash_df_return_value.status;
  C = hash_df_return_value.requested_bits;
  reseed_counter = 1;

  return ReturnStatus::kSUCCESS;
}

HASH_DRBG::ReturnStatus HASH_DRBG::ReseedAlgorithm(
    const std::vector<std::byte>& additional_input,
    const std::uint64_t& additional_input_length) {}

HASH_DRBG::GenerateReturnValue HASH_DRBG::GenerateAlgorithm(
    const std::uint64_t& requested_number_of_bits,
    const std::vector<std::byte>& additional_input,
    const std::uint64_t& additional_input_length) {}

HASH_DRBG::HashDFReturnValue HASH_DRBG::Hash_df(
    std::vector<std::byte> input_string, std::uint32_t no_of_bits_to_return) {}
}  // namespace file_encrypt::algorithm