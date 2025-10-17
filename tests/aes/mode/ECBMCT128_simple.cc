#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _TEST_TYPE "simple"

#define _KEY_BIT 128
#define _ALGORITHM file_encrypt::algorithm::AES_128_ECB<10>
#define _TESTDIRECTORY_PREFIX "./tests/test_vector/"
#define _TESTDIRECTORY "aesmct/"
#define _TEST_NAME "ECBMCT128"
#define _TESTFILEEXT ".rsp"

int main() {
  std::vector<NISTTestVectorParser::NISTTestMonteStage> encrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherMonteVector(
          _TESTDIRECTORY_PREFIX _TESTDIRECTORY _TEST_NAME _TESTFILEEXT,
          encrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kEncrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            encrypt_test_vectors.back().variable.binary["error_msg"].data()),
        encrypt_test_vectors.back().variable.binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }
  std::vector<NISTTestVectorParser::NISTTestMonteStage> decrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherMonteVector(
          _TESTDIRECTORY_PREFIX _TESTDIRECTORY _TEST_NAME _TESTFILEEXT,
          decrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kDecrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            decrypt_test_vectors.back().variable.binary["error_msg"].data()),
        decrypt_test_vectors.back().variable.binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::vector<std::byte> input_block;
  file_encrypt::algorithm::op_mode::OperationModeOutputData<128> output_block;
  input_block.resize(16);

  std::cout << _TEST_NAME " " _TEST_TYPE " Encryption:" << std::endl;
  for (auto item : encrypt_test_vectors) {
    std::vector<std::byte> prev_result;
    prev_result.resize(item.variable.binary["PLAINTEXT"].size());
    std::array<std::byte, _KEY_BIT / 8> key;
    std::memcpy(key.data(), item.variable.binary["KEY"].data(), _KEY_BIT / 8);

    _ALGORITHM cipher(key);
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;

    std::copy(item.variable.binary["PLAINTEXT"].begin(),
              item.variable.binary["PLAINTEXT"].end(), prev_result.begin());

    std::uint32_t stage_number = item.variable.integer["COUNT"];

    std::cout << stage_number + 1;
    if ((stage_number + 1) % 10 == 1 && (stage_number + 1) != 11) {
      std::cout << "st ";
    } else if ((stage_number + 1) % 10 == 2 && (stage_number + 1) != 12) {
      std::cout << "nd ";
    } else if ((stage_number + 1) % 10 == 3 && (stage_number + 1) != 13) {
      std::cout << "rd ";
    } else {
      std::cout << "th ";
    }
    std::cout << "stage: " << "\n";

    std::cout << "KEY: "
              << file_encrypt::util::BytesToStr(item.variable.binary["KEY"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << file_encrypt::util::BytesToStr(
                     item.variable.binary["PLAINTEXT"])
              << "\n";

    for (int i = 0; i < 1000; i++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());
      for (int j = 0;; j++) {
        if (j * 16 + 16 > prev_result.size()) {
          break;
        }
        std::copy(j * 16 + prev_result.begin(),
                  j * 16 + prev_result.begin() + 16, input_block.begin());
        cipher << input_block;
        cipher >> output_block;
        std::copy(output_block.data.begin(), output_block.data.end(),
                  std::back_inserter(result));
      }
      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == i) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << i << "\n";
        std::cout << "\t" << "Intermediate expected CIPHERTEXT: "
                  << file_encrypt::util::BytesToStr(
                         sample.variable.binary["Intermediate Vaue CIPHERTEXT"])
                  << "\n";
        std::cout << "\t" << "Intermediate Vaue CIPHERTEXT: "
                  << file_encrypt::util::BytesToStr(result) << "\n";

        if (result != sample.variable.binary["Intermediate Vaue CIPHERTEXT"]) {
          std::cout << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }
      prev_result = result;
    }

    std::cout << "EXPECTED CIPHERTEXT: "
              << file_encrypt::util::BytesToStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: " << file_encrypt::util::BytesToStr(prev_result)
              << "\n";

    if (prev_result != item.variable.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << _TEST_NAME " " _TEST_TYPE " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::vector<std::byte> prev_result;
    prev_result.resize(item.variable.binary["CIPHERTEXT"].size());
    std::array<std::byte, _KEY_BIT / 8> key;
    std::memcpy(key.data(), item.variable.binary["KEY"].data(), _KEY_BIT / 8);

    _ALGORITHM cipher(key);
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;

    std::copy(item.variable.binary["CIPHERTEXT"].begin(),
              item.variable.binary["CIPHERTEXT"].end(), prev_result.begin());

    std::uint32_t stage_number = item.variable.integer["COUNT"];

    std::cout << stage_number + 1;
    if ((stage_number + 1) % 10 == 1 && (stage_number + 1) != 11) {
      std::cout << "st ";
    } else if ((stage_number + 1) % 10 == 2 && (stage_number + 1) != 12) {
      std::cout << "nd ";
    } else if ((stage_number + 1) % 10 == 3 && (stage_number + 1) != 13) {
      std::cout << "rd ";
    } else {
      std::cout << "th ";
    }
    std::cout << "stage: " << "\n";

    std::cout << "KEY: "
              << file_encrypt::util::BytesToStr(item.variable.binary["KEY"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";

    for (int i = 0; i < 1000; i++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["CIPHERTEXT"].size());
      for (int j = 0;; j++) {
        if (j * 16 + 16 > prev_result.size()) {
          break;
        }
        std::copy(j * 16 + prev_result.begin(),
                  j * 16 + prev_result.begin() + 16, input_block.begin());
        cipher << input_block;
        cipher >> output_block;
        std::copy(output_block.data.begin(), output_block.data.end(),
                  std::back_inserter(result));
      }
      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == i) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << i << "\n";
        std::cout << "\t" << "Intermediate expected PLAINTEXT: "
                  << file_encrypt::util::BytesToStr(
                         sample.variable.binary["Intermediate Vaue PLAINTEXT"])
                  << "\n";
        std::cout << "\t" << "Intermediate Vaue PLAINTEXT: "
                  << file_encrypt::util::BytesToStr(result) << "\n";

        if (result != sample.variable.binary["Intermediate Vaue PLAINTEXT"]) {
          std::cout << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }
      prev_result = result;
    }

    std::cout << "EXPECTED PLAINTEXT: "
              << file_encrypt::util::BytesToStr(
                     item.variable.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: " << file_encrypt::util::BytesToStr(prev_result)
              << "\n";

    if (prev_result != item.variable.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}