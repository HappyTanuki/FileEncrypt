#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _KEY_BIT 128
#define _ALGORITHM file_encrypt::algorithm::AES128_CBC<10>
#define _TESTDIRECTORY_PREFIX "./tests/test_vector/"
#define _TESTDIRECTORY "KAT_AES/"
#define _TEST_NAME "CBCVarTxt128"
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
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(IV.data(), item.binary["IV"].data(), 16);

    _ALGORITHM cipher(key, IV);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> output_block;
    std::vector<std::byte> input_block;
    std::array<std::byte, 16> expected_block;
    input_block.resize(16);
    std::vector<std::byte> result;
    result.reserve(item.binary["CIPHERTEXT"].size());
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;

    std::cout << "KEY: " << file_encrypt::util::BytesToStr(item.binary["KEY"])
              << "\n";
    std::cout << "IV: " << file_encrypt::util::BytesToStr(item.binary["IV"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << file_encrypt::util::BytesToStr(item.binary["PLAINTEXT"])
              << "\n";

    for (int i = 0;; i++) {
      if (i * 16 + 16 > item.binary["PLAINTEXT"].size()) {
        break;
      }
      std::copy(i * 16 + item.binary["PLAINTEXT"].begin(),
                i * 16 + item.binary["PLAINTEXT"].begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary["CIPHERTEXT"].begin(),
                i * 16 + item.binary["CIPHERTEXT"].begin() + 16,
                expected_block.begin());
      cipher << input_block;
      cipher >> output_block;
      std::copy(output_block.data.begin(), output_block.data.end(),
                std::back_inserter(result));
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "PLAINTEXT block: "
                << file_encrypt::util::BytesToStr(input_block) << "\n";
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "expected block: "
                << file_encrypt::util::BytesToStr<16>(expected_block) << "\n";
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "CIPHERTEXT block: "
                << file_encrypt::util::BytesToStr<16>(output_block.data)
                << "\n";
      if (output_block.data != expected_block) {
        std::cout << "\t" << "Mismatch" << std::endl;
        return -1;
      }
    }

    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: " << file_encrypt::util::BytesToStr(result)
              << "\n";

    if (result != item.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << _TEST_NAME " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::array<std::byte, _KEY_BIT / 8> key;
    std::array<std::byte, 16> IV;
    std::memcpy(key.data(), item.binary["KEY"].data(), _KEY_BIT / 8);
    std::memcpy(IV.data(), item.binary["IV"].data(), 16);

    _ALGORITHM cipher(key, IV);
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> output_block;
    std::vector<std::byte> input_block;
    std::array<std::byte, 16> expected_block;
    input_block.resize(16);
    std::vector<std::byte> result;
    result.reserve(item.binary["PLAINTEXT"].size());
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;

    std::cout << "KEY: " << file_encrypt::util::BytesToStr(item.binary["KEY"])
              << "\n";
    std::cout << "IV: " << file_encrypt::util::BytesToStr(item.binary["IV"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToStr(item.binary["CIPHERTEXT"])
              << "\n";

    for (int i = 0;; i++) {
      if (i * 16 + 16 > item.binary["CIPHERTEXT"].size()) {
        break;
      }
      std::copy(i * 16 + item.binary["CIPHERTEXT"].begin(),
                i * 16 + item.binary["CIPHERTEXT"].begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary["PLAINTEXT"].begin(),
                i * 16 + item.binary["PLAINTEXT"].begin() + 16,
                expected_block.begin());
      cipher << input_block;
      cipher >> output_block;
      std::copy(output_block.data.begin(), output_block.data.end(),
                std::back_inserter(result));
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "CIPHERTEXT block: "
                << file_encrypt::util::BytesToStr(input_block) << "\n";
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "expected block: "
                << file_encrypt::util::BytesToStr<16>(expected_block) << "\n";
      std::cout << "\t" << i + 1;
      if ((i + 1) % 10 == 1 && (i + 1) != 11) {
        std::cout << "st ";
      } else if ((i + 1) % 10 == 2 && (i + 1) != 12) {
        std::cout << "nd ";
      } else if ((i + 1) % 10 == 3 && (i + 1) != 13) {
        std::cout << "rd ";
      } else {
        std::cout << "th ";
      }
      std::cout << "PLAINTEXT block: "
                << file_encrypt::util::BytesToStr<16>(output_block.data)
                << "\n";
      if (output_block.data != expected_block) {
        std::cout << "\t" << "Mismatch" << std::endl;
        return -1;
      }
    }

    std::cout << "EXPECTED: "
              << file_encrypt::util::BytesToStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: " << file_encrypt::util::BytesToStr(result)
              << "\n";

    if (result != item.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}