#include <string>

#include "algorithm/block_cipher/aes.h"
#include "util/helper.h"

int main() {
  file_encrypt::algorithm::AES<256> aes;
  std::array<std::byte, 16> data = {};
  std::array<std::byte, 32> key = {};
  data =
      file_encrypt::util::HexStrToBytes<16>("014730f80ac625fe84f026c60bfd547d");
  key = file_encrypt::util::HexStrToBytes<32>(
      "0000000000000000000000000000000000000000000000000000000000000000");

  auto result = aes.Encrypt(data, key);

  auto expected_result =
      file_encrypt::util::HexStrToBytes<16>("5c9d844ed46f9885085e5d6a4f94c7d7");

  if (result != expected_result) {
    return -1;
  }

  data = {};
  key = file_encrypt::util::HexStrToBytes<32>(
      "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");

  result = aes.Encrypt(data, key);

  expected_result =
      file_encrypt::util::HexStrToBytes<16>("46f2fb342d6f0ab477476fc501242c5f");

  if (result != expected_result) {
    return -1;
  }

  data =
      file_encrypt::util::HexStrToBytes<16>("46f2fb342d6f0ab477476fc501242c5f");
  key = file_encrypt::util::HexStrToBytes<32>(
      "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");

  result = aes.Decrypt(data, key);

  expected_result =
      file_encrypt::util::HexStrToBytes<16>("00000000000000000000000000000000");

  if (result != expected_result) {
    return -1;
  }

  return 0;
}