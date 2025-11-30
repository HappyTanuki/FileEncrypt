#include <cstring>

#include "algorithm/algorithm.h"
#include "hash_drbg.h"
#include "util/helper.h"

namespace file_encrypt::algorithm {

using file_encrypt::util::ConcatByteVectors;

template <std::uint32_t HashDigestLen>
HASH_DRBG<HashDigestLen>::HASH_DRBG(
    std::unique_ptr<HashAlgorithm<HashDigestLen>> algorithm) {
  hash = std::move(algorithm);
}

template <std::uint32_t HashDigestLen>
ReturnStatus HASH_DRBG<HashDigestLen>::InstantiateAlgorithm(
    const std::vector<std::byte>& entropy_input, std::vector<std::byte> nonce,
    const std::vector<std::byte>& personalization_string,
    const std::uint32_t& security_strangth) {
  std::vector<std::byte> seed_material;
  std::vector<std::byte> seed;

  seed_material =
      ConcatByteVectors(entropy_input, nonce, personalization_string);

  // Ignore statuscode because there is no explicit mention in SP 800-90A
  seed = Hash_df(seed_material, seedlen).requested_bits;
  V = seed;

  C = Hash_df(
          ConcatByteVectors(file_encrypt::util::UInt8ToBytesVector(0x00), V),
          seedlen)
          .requested_bits;
  reseed_counter = 1;

  return ReturnStatus::kSUCCESS;
}

// This function shall not return failure status
template <std::uint32_t HashDigestLen>
ReturnStatus HASH_DRBG<HashDigestLen>::ReseedAlgorithm(
    const std::vector<std::byte>& entropy_input,
    const std::vector<std::byte>& additional_input) {
  std::vector<std::byte> seed;
  std::vector<std::byte> seed_material;

  seed_material =
      ConcatByteVectors(file_encrypt::util::UInt8ToBytesVector(0x01), V,
                        entropy_input, additional_input);

  HashDFReturnValue hash_df_return_value;
  // Ignore statuscode because there is no explicit mention in SP 800-90A
  seed = Hash_df(seed_material, seedlen).requested_bits;
  V = seed;

  C = Hash_df(
          ConcatByteVectors(file_encrypt::util::UInt8ToBytesVector(0x00), V),
          seedlen)
          .requested_bits;
  reseed_counter = 1;

  return ReturnStatus::kSUCCESS;
}

template <std::uint32_t HashDigestLen>
HASH_DRBG<HashDigestLen>::GenerateReturnValue
HASH_DRBG<HashDigestLen>::GenerateAlgorithm(
    const std::uint64_t& requested_number_of_bits,
    const std::vector<std::byte>& additional_input) {
  std::vector<std::byte> w = {};

  if (reseed_counter > reseed_interval)
    return {ReturnStatus::kRESEED_REQUIRED, {}};
  if (additional_input.size() != 0) {
    std::vector<std::byte> temp = ConcatByteVectors(
        file_encrypt::util::UInt8ToBytesVector(0x02), V, additional_input);

    HashAlgorithmReturnData hash_algorithm_return_data;
    hash_algorithm_return_data = hash->Digest({temp, temp.size() * 8});
    w = hash_algorithm_return_data.digest;

    V = file_encrypt::util::MaskSeedlen(
        file_encrypt::util::AddByteVectors(V, w), seedlen);
  }

  std::vector<std::byte> returned_bits =
      Hashgen(requested_number_of_bits, V).returned_bits;

  std::vector<std::byte> temp =
      ConcatByteVectors(file_encrypt::util::UInt8ToBytesVector(0x03), V);
  std::vector<std::byte> H = hash->Digest({temp, temp.size() * 8}).digest;

  V = file_encrypt::util::MaskSeedlen(
      file_encrypt::util::AddByteVectors(
          V, H, C, file_encrypt::util::UInt32ToBytesVector(reseed_counter)),
      seedlen);
  reseed_counter++;
  return {ReturnStatus::kSUCCESS, returned_bits};
}

template <std::uint32_t HashDigestLen>
HASH_DRBG<HashDigestLen>::HashDFReturnValue HASH_DRBG<HashDigestLen>::Hash_df(
    std::vector<std::byte> input_string, std::uint32_t no_of_bits_to_return) {
  std::vector<std::byte> temp = {};
  std::uint32_t len = (no_of_bits_to_return + outlen - 1) / outlen;
  std::uint8_t counter = 0x01;

  for (std::uint32_t i = 1; i <= len; i++) {
    std::vector<std::byte> concat = ConcatByteVectors(
        file_encrypt::util::UInt8ToBytesVector(counter),
        file_encrypt::util::UInt32ToBytesVector(no_of_bits_to_return),
        input_string);
    std::vector<std::byte> digest =
        hash->Digest({concat, concat.size() * 8}).digest;
    temp = ConcatByteVectors(temp, digest);
    counter++;
  }

  return {ReturnStatus::kSUCCESS,
          file_encrypt::util::Leftmost(temp, no_of_bits_to_return)};
}

template <std::uint32_t HashDigestLen>
HASH_DRBG<HashDigestLen>::HashgenReturnValue HASH_DRBG<HashDigestLen>::Hashgen(
    std::uint64_t requested_no_of_bits, std::vector<std::byte> V) {
  std::uint64_t m = (requested_no_of_bits + outlen - 1) / outlen;
  std::vector<std::byte> data = V;
  std::vector<std::byte> W = {};
  for (std::uint64_t i = 1; i <= m; ++i) {
    auto w = hash->Digest({data, data.size() * 8}).digest;
    W = ConcatByteVectors(W, w);
    data = file_encrypt::util::MaskSeedlen(
        file_encrypt::util::AddByteVectors(
            data, file_encrypt::util::UInt8ToBytesVector(0x01)),
        seedlen);
  }

  return {file_encrypt::util::Leftmost(W, requested_no_of_bits)};
}
}  // namespace file_encrypt::algorithm