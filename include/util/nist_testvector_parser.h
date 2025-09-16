#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <queue>
#include <string>
#include <vector>

#include "algorithm/algorithm.h"

namespace file_encrypt::util::NISTTestVectorParser {

enum class ReturnStatusCode { kSuccess = 0, kError = -1 };

struct NISTTestVector {
  std::vector<std::byte> Msg = {};
  std::uint64_t Len = 0;
  std::vector<std::byte> MD = {};
};

struct NISTTestMonteSample {
  std::uint32_t i = 0;
  std::vector<std::byte> M = {};
  std::vector<std::byte> MDi = {};
};

struct NISTTestMonteStage {
  std::uint32_t count = 0;
  std::queue<NISTTestMonteSample> samples = {};
};

struct NISTTestMonteVector {
  std::vector<std::byte> seed = {};
  std::vector<NISTTestMonteStage> stage = {};
  std::vector<std::vector<std::byte>> MD = {};
  ReturnStatusCode return_code = ReturnStatusCode::kError;
};

std::vector<NISTTestVector> ParseMsg(const std::filesystem::path& file_path);
NISTTestMonteVector ParseMonte(const std::filesystem::path& file_path);

}  // namespace file_encrypt::util::NISTTestVectorParser

#endif