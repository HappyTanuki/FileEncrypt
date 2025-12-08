#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _KEY_BIT 128
#define _ALGORITHM file_encrypt::algorithm::AES_CBC<128>
#define _TESTDIRECTORY_PREFIX "./tests/test_vector/"
#define _TESTDIRECTORY "KAT_AES/"
#define _TEST_NAME "CBCGFSbox128"
#define _TESTFILEEXT ".rsp"

int main() {
  std::vector<NISTTestVectorParser::NISTTestVariables> encrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherVector(
          _TESTDIRECTORY_PREFIX _TESTDIRECTORY _TEST_NAME _TESTFILEEXT,
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
          _TESTDIRECTORY_PREFIX _TESTDIRECTORY _TEST_NAME _TESTFILEEXT,
          decrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kDecrypt) !=
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
    std::array<std::byte, 16> IV;
    std::array<std::byte, 16> expected;
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(IV.data(), item.binary["IV"].data(), 16);
    std::memcpy(expected.data(), item.binary["CIPHERTEXT"].data(), 16);

    _ALGORITHM cipher(key, IV);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;
    cipher << item.binary["PLAINTEXT"];
    cipher >> result;

    std::cout << "KEY: "
              << file_encrypt::util::BytesToHexStr(item.binary["KEY"]) << "\n";
    std::cout << "PLAINTEXT: "
              << file_encrypt::util::BytesToHexStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToHexStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "RESULT: " << file_encrypt::util::BytesToHexStr(result.data)
              << "\n";

    if (result.data != expected) {
      std::cout << "Mismatch";
      return -1;
    }
  }
  std::cout << _TEST_NAME " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::array<std::byte, _KEY_BIT / 8> key;
    std::array<std::byte, 16> IV;
    std::array<std::byte, 16> expected;
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(IV.data(), item.binary["IV"].data(), 16);
    std::memcpy(expected.data(), item.binary["PLAINTEXT"].data(), 16);

    _ALGORITHM cipher(key, IV);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> result;
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;
    cipher << item.binary["CIPHERTEXT"];
    cipher >> result;

    std::cout << "KEY: "
              << file_encrypt::util::BytesToHexStr(item.binary["KEY"]) << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToHexStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToHexStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "RESULT: " << file_encrypt::util::BytesToHexStr(result.data)
              << "\n";

    if (result.data != expected) {
      std::cout << "Mismatch";
      return -1;
    }
  }

  return 0;
}