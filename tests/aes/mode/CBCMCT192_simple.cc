#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _TEST_TYPE "simple"

#define _KEY_BIT 192
#define _ALGORITHM file_encrypt::algorithm::AES_192_CBC<10>
#define _TESTDIRECTORY_PREFIX "./tests/test_vector/"
#define _TESTDIRECTORY "aesmct/"
#define _TEST_NAME "CBCMCT192"
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

  std::vector<std::byte> prev_result;
  std::vector<std::byte> prev_prev_result;

  std::cout << _TEST_NAME " " _TEST_TYPE " Encryption:" << std::endl;
  for (int i = 0; i < encrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = encrypt_test_vectors[i];
    std::array<std::byte, _KEY_BIT / 8> key;
    if (i == 0) {
      std::memcpy(key.data(), item.variable.binary["KEY"].data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 128) {
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], prev_result);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 192) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 256) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    }
    std::array<std::byte, 16> IV;
    std::memcpy(IV.data(), item.variable.binary["IV"].data(), 16);

    _ALGORITHM cipher(key, IV);
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;

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
              << file_encrypt::util::BytesToHexStr(item.variable.binary["KEY"])
              << " (" << std::to_integer<int>(item.variable.binary["KEY"][0])
              << ", " << std::to_integer<int>(item.variable.binary["KEY"][1])
              << " ... "
              << std::to_integer<int>(item.variable.binary["KEY"][14]) << ", "
              << std::to_integer<int>(item.variable.binary["KEY"][15]) << ") "
              << "\n";
    std::cout << "IV: "
              << file_encrypt::util::BytesToHexStr(item.variable.binary["IV"])
              << " (" << std::to_integer<int>(item.variable.binary["IV"][0])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][1])
              << " ... " << std::to_integer<int>(item.variable.binary["IV"][14])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][15])
              << ") "
              << "\n";
    std::cout << "PLAINTEXT: "
              << file_encrypt::util::BytesToHexStr(
                     item.variable.binary["PLAINTEXT"])
              << " ("
              << std::to_integer<int>(item.variable.binary["PLAINTEXT"][0])
              << ", "
              << std::to_integer<int>(item.variable.binary["PLAINTEXT"][1])
              << " ... "
              << std::to_integer<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 2])
              << ", "
              << std::to_integer<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::byte> next_input;
    next_input.resize(item.variable.binary["PLAINTEXT"].size());
    std::memcpy(next_input.data(), item.variable.binary["PLAINTEXT"].data(),
                item.variable.binary["PLAINTEXT"].size());

    for (int i = 0; i < 1000; i++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (int j = 0; j * 16 + 16 <= next_input.size(); j++) {
        std::vector<std::byte> input_block(16);
        std::copy(j * 16 + next_input.begin(), j * 16 + next_input.begin() + 16,
                  input_block.begin());
        file_encrypt::algorithm::op_mode::OperationModeOutputData<128>
            output_block;
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
        std::cout
            << "\t" << "Intermediate expected CIPHERTEXT: "
            << file_encrypt::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"])
            << " ("
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][0])
            << ", "
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][1])
            << " ... "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               2])
            << ", "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue CIPHERTEXT: "
                  << file_encrypt::util::BytesToHexStr(result) << " ("
                  << std::to_integer<int>(result[0]) << ", "
                  << std::to_integer<int>(result[1]) << " ... "
                  << std::to_integer<int>(result[result.size() - 2]) << ", "
                  << std::to_integer<int>(result[result.size() - 1]) << ") "
                  << "\n";

        if (result != sample.variable.binary["Intermediate Vaue CIPHERTEXT"]) {
          std::cout << "\t" << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }

      if (i == 0) {
        next_input = item.variable.binary["IV"];
      } else {
        next_input = prev_result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }

    std::cout << "EXPECTED CIPHERTEXT: "
              << file_encrypt::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToHexStr(prev_result) << "\n";

    if (prev_result != item.variable.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << _TEST_NAME " " _TEST_TYPE " Decryption:" << std::endl;
  for (int i = 0; i < decrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = decrypt_test_vectors[i];
    std::array<std::byte, _KEY_BIT / 8> key;
    if (i == 0) {
      std::memcpy(key.data(), item.variable.binary["KEY"].data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 128) {
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], prev_result);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 192) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    } else if (_KEY_BIT == 256) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = file_encrypt::util::XorVectors(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::memcpy(key.data(), temp_key.data(), _KEY_BIT / 8);
    }
    std::array<std::byte, 16> IV;
    std::memcpy(IV.data(), item.variable.binary["IV"].data(), 16);

    _ALGORITHM cipher(key, IV);
    cipher << file_encrypt::algorithm::op_mode::CipherMode::Decrypt;

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
              << file_encrypt::util::BytesToHexStr(item.variable.binary["KEY"])
              << " (" << std::to_integer<int>(item.variable.binary["KEY"][0])
              << ", " << std::to_integer<int>(item.variable.binary["KEY"][1])
              << " ... "
              << std::to_integer<int>(item.variable.binary["KEY"][14]) << ", "
              << std::to_integer<int>(item.variable.binary["KEY"][15]) << ") "
              << "\n";
    std::cout << "IV: "
              << file_encrypt::util::BytesToHexStr(item.variable.binary["IV"])
              << " (" << std::to_integer<int>(item.variable.binary["IV"][0])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][1])
              << " ... " << std::to_integer<int>(item.variable.binary["IV"][14])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][15])
              << ") "
              << "\n";
    std::cout << "CIPHERTEXT: "
              << file_encrypt::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << " ("
              << std::to_integer<int>(item.variable.binary["CIPHERTEXT"][0])
              << ", "
              << std::to_integer<int>(item.variable.binary["CIPHERTEXT"][1])
              << " ... "
              << std::to_integer<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 2])
              << ", "
              << std::to_integer<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::byte> next_input;
    next_input.resize(item.variable.binary["CIPHERTEXT"].size());
    std::memcpy(next_input.data(), item.variable.binary["CIPHERTEXT"].data(),
                item.variable.binary["CIPHERTEXT"].size());

    for (int i = 0; i < 1000; i++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (int j = 0; j * 16 + 16 <= next_input.size(); j++) {
        std::vector<std::byte> input_block(16);
        std::copy(j * 16 + next_input.begin(), j * 16 + next_input.begin() + 16,
                  input_block.begin());
        file_encrypt::algorithm::op_mode::OperationModeOutputData<128>
            output_block;
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
        std::cout
            << "\t" << "Intermediate expected PLAINTEXT: "
            << file_encrypt::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"])
            << " ("
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][0])
            << ", "
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][1])
            << " ... "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               2])
            << ", "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue PLAINTEXT: "
                  << file_encrypt::util::BytesToHexStr(result) << " ("
                  << std::to_integer<int>(result[0]) << ", "
                  << std::to_integer<int>(result[1]) << " ... "
                  << std::to_integer<int>(result[result.size() - 2]) << ", "
                  << std::to_integer<int>(result[result.size() - 1]) << ") "
                  << "\n";

        if (result != sample.variable.binary["Intermediate Vaue PLAINTEXT"]) {
          std::cout << "\t" << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }

      if (i == 0) {
        next_input = item.variable.binary["IV"];
      } else {
        next_input = prev_result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }

    std::cout << "EXPECTED PLAINTEXT: "
              << file_encrypt::util::BytesToHexStr(
                     item.variable.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: " << file_encrypt::util::BytesToHexStr(prev_result)
              << "\n";

    if (prev_result != item.variable.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}