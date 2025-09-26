#include <string>

#include "algorithm/block_cipher/aes.h"

std::vector<std::byte> HexStringToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

int main() {
  file_encrypt::algorithm::AES<256> aes;
  file_encrypt::algorithm::CipherAlgorithmInputData input;
  input.data = HexStringToBytes("014730f80ac625fe84f026c60bfd547d");
  input.key.resize(32);

  auto result = aes.Encrypt(input);

  auto expected_result = HexStringToBytes("5c9d844ed46f9885085e5d6a4f94c7d7");

  if (result.data != expected_result) {
    return -1;
  }

  input.data.clear();
  input.data.resize(16);
  input.key = HexStringToBytes(
      "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");

  result = aes.Encrypt(input);

  expected_result = HexStringToBytes("46f2fb342d6f0ab477476fc501242c5f");

  if (result.data != expected_result) {
    return -1;
  }

  input.data.clear();
  input.data = HexStringToBytes("46f2fb342d6f0ab477476fc501242c5f");
  input.key.clear();
  input.key = HexStringToBytes(
      "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");

  result = aes.Decrypt(input);

  expected_result = HexStringToBytes("00000000000000000000000000000000");

  if (result.data != expected_result) {
    return -1;
  }

  return 0;
}