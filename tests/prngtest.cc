#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "util/helper.h"

int main() {
  file_encrypt::algorithm::DRBG_SHA256 prng;
  std::vector<std::byte> entropy(32);
  file_encrypt::algorithm::CSPRNG::GetRandom(
      reinterpret_cast<char*>(entropy.data()), 32);
  prng.Instantiate(256, true, {}, {}, entropy);

  entropy.resize(16);
  file_encrypt::algorithm::CSPRNG::GetRandom(
      reinterpret_cast<char*>(entropy.data()), 16);

  std::array<std::byte, 16> pseudorandom_bits = {};

  for (int i = 1; i <= 1000; i++) {
    file_encrypt::algorithm::CSPRNG::GenerateReturnValue generate_return_value =
        prng.Generate(128, 256, true, entropy);
    if (generate_return_value.status ==
        file_encrypt::algorithm::ReturnStatus::kRESEED_REQUIRED) {
      file_encrypt::algorithm::CSPRNG::GetRandom(
          reinterpret_cast<char*>(entropy.data()), 16);
      std::cout << "Reseeding..." << std::endl;
      prng.Reseed(true, entropy);
    }

    std::cout << std::setw(4) << std::setfill('0') << i
              << file_encrypt::util::GetEnglishNumberSufix(i)
              << " random bits: "
              << file_encrypt::util::BytesToHexStr(
                     generate_return_value.pseudorandom_bits)
              << std::endl;
  }

  return 0;
}