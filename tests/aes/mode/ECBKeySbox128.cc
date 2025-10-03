#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _KEY_BIT 128
#define _TEST_NAME "ECBKeySbox128"

int main() {
  std::vector<NISTTestVectorParser::NISTTestVariables> encrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherVector(
          "./tests/test_vector/KAT_AES/" _TEST_NAME ".rsp",
          encrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kEncrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            encrypt_test_vectors.back().binary["error_msg"].data()),
        encrypt_test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }
  std::vector<NISTTestVectorParser::NISTTestVariables> decrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherVector(
          "./tests/test_vector/KAT_AES/" _TEST_NAME ".rsp",
          decrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kEncrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            decrypt_test_vectors.back().binary["error_msg"].data()),
        decrypt_test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << _TEST_NAME " Encryption:" << std::endl;
  for (auto item : encrypt_test_vectors) {
    std::array<std::byte, _KEY_BIT / 8> key;
    std::array<std::byte, 16> expected;
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(expected.data(), item.binary["CIPHERTEXT"].data(), 16);

    file_encrypt::algorithm::AES128_ECB<10> cipher(key);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;
    cipher << item.binary["PLAINTEXT"];
    cipher >> result;

    std::cout << "KEY: " << file_encrypt::util::BytesToStr(item.binary["KEY"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << file_encrypt::util::BytesToStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "RESULT: " << file_encrypt::util::BytesToStr<16>(result.data)
              << "\n";

    if (result.data != expected) {
      std::cout << "Mismatch";
      return -1;
    }
  }
  std::cout << _TEST_NAME " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::array<std::byte, _KEY_BIT / 8> key;
    std::array<std::byte, 16> expected;
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(expected.data(), item.binary["PLAINTEXT"].data(), 16);

    file_encrypt::algorithm::AES128_ECB<10> cipher(key);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;
    cipher << item.binary["CIPHERTEXT"];
    cipher >> result;

    std::cout << "KEY: " << file_encrypt::util::BytesToStr(item.binary["KEY"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "RESULT: " << file_encrypt::util::BytesToStr<16>(result.data)
              << "\n";

    if (result.data != expected) {
      std::cout << "Mismatch";
      return -1;
    }
  }

  return 0;
}