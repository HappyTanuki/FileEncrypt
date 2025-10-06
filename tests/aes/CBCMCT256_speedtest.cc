#include <ctime>
#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "util/helper.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

#define _TEST_TYPE "complex"

#define _KEY_BIT 256
#define _ALGORITHM file_encrypt::algorithm::AES256_CBC<10>
#define _TESTDIRECTORY_PREFIX "./tests/test_vector/"
#define _TESTDIRECTORY "aesmct_intermediate/"
#define _TEST_NAME "CBCMCT256"
#define _TESTFILEEXT ".txt"

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

  std::vector<std::byte> prev_result;
  std::vector<std::byte> prev_prev_result;

  auto start_time = std::clock();

  _ALGORITHM cipher;
  cipher << file_encrypt::algorithm::op_mode::CipherMode::Encrypt;

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

    cipher.SetKey(key);
    cipher.SetIV(IV);

    std::vector<std::byte> next_input;
    next_input.resize(item.variable.binary["PLAINTEXT"].size());
    std::memcpy(next_input.data(), item.variable.binary["PLAINTEXT"].data(),
                item.variable.binary["PLAINTEXT"].size());

    std::vector<std::byte> result;
    result.resize(next_input.size());
    file_encrypt::algorithm::op_mode::OperationModeOutputData<128> output_block;
    std::vector<std::byte> input_block(16);

    for (int j = 0; j < 1000000; j++) {
      // next_input의 블록 수
      size_t blocks = next_input.size() / 16;
      // result에 쓸 위치 포인터
      size_t write_pos = 0;

      // 블록 단위로 처리. 복사 최소화: 메모리에서 직접 복사하여 AES API에 전달
      const std::byte* in_ptr = next_input.data();
      for (size_t b = 0; b < blocks; ++b) {
        // input_block에 복사 (memcpy는 빠름, avoid vector ctor)
        std::memcpy(input_block.data(), in_ptr + b * 16, 16);

        // 암호화 API 사용 (기존 operator<< / >> 유지)
        cipher << input_block;
        cipher >> output_block;

        // output_block.data는 컨테이너. 한 번에 메모리 복사
        std::memcpy(result.data() + write_pos, output_block.data.data(), 16);
        write_pos += 16;
      }

      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == j) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();
      }

      if (j == 0) {
        next_input = item.variable.binary["IV"];
      } else {
        next_input = prev_result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }
  }

  auto end_time = std::clock();
  double elapsed_time = double(end_time - start_time) / CLOCKS_PER_SEC;
  std::cout << "Elapsed time: " << elapsed_time << " seconds" << std::endl;

  return 0;
}