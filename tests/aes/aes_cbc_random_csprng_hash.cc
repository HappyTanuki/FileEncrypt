#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "util/helper.h"

int main() {
  {  // AES_256_ECB
    std::array<std::byte, 16> expected_result = {};

    file_encrypt::algorithm::DRBG_SHA256 prng =
        file_encrypt::algorithm::DRBG_SHA256();
    std::vector<std::byte> entropy(32);
    file_encrypt::algorithm::CSPRNG::GetRandom(
        reinterpret_cast<char*>(entropy.data()), 32);
    prng.Instantiate(256, true, {}, {}, entropy);

    entropy.resize(16);
    file_encrypt::algorithm::CSPRNG::GetRandom(
        reinterpret_cast<char*>(entropy.data()), 16);

    std::array<std::byte, 16> pseudorandom_bits = {};
    file_encrypt::algorithm::CSPRNG::GenerateReturnValue generate_return_value =
        prng.Generate(128, 256, true, entropy);

    std::memcpy(pseudorandom_bits.data(),
                generate_return_value.pseudorandom_bits.data(),
                generate_return_value.pseudorandom_bits.size());

    file_encrypt::algorithm::AES_CBC<256> cipher(
        file_encrypt::util::HexStrToBytes<32>(""), pseudorandom_bits);
    auto IV = cipher.IV;

    cipher << file_encrypt::util::HexStrToBytes(
        "014730f80ac625fe84f026c60bfd547d");
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher >> result;

    std::cout << file_encrypt::util::BytesToHexStr<std::array<std::byte, 16>>(
                     result.data)
              << std::endl;

    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;

    cipher.SetIV(IV);

    cipher << file_encrypt::util::HexStrToBytes(
        file_encrypt::util::BytesToHexStr<std::array<std::byte, 16>>(
            result.data));
    expected_result = file_encrypt::util::HexStrToBytes<16>(
        "014730f80ac625fe84f026c60bfd547d");
    cipher >> result;

    if (result.data != expected_result) {
      return -1;
    }
  }
  return 0;
}