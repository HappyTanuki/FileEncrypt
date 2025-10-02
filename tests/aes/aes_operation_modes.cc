#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"

int main() {
  {  // AES256_ECB
    file_encrypt::algorithm::AES256_ECB<10> cipher(
        file_encrypt::util::HexStringToBytes<32>(""));

    cipher << file_encrypt::util::HexStringToBytes(
        "014730f80ac625fe84f026c60bfd547d");
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher >> result;

    auto expected_result = file_encrypt::util::HexStringToBytes<16>(
        "5c9d844ed46f9885085e5d6a4f94c7d7");

    if (result.data != expected_result) {
      return -1;
    }

    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;

    cipher << file_encrypt::util::HexStringToBytes(
        "5c9d844ed46f9885085e5d6a4f94c7d7");
    expected_result = file_encrypt::util::HexStringToBytes<16>(
        "014730f80ac625fe84f026c60bfd547d");
    cipher >> result;

    if (result.data != expected_result) {
      return -1;
    }
  }
  return 0;
}