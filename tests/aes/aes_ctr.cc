#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"

int main() {
  {  // AES_256_ECB
    std::array<std::byte, 16> expected_result = {};

    file_encrypt::algorithm::AES_CTR<256> cipher(
        file_encrypt::util::HexStrToBytes<32>(""));
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