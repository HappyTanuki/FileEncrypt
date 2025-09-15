#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace file_encrypt::util::NISTTestVectorParser {

struct NISTTestVector {
  std::vector<std::byte> input;
  std::vector<std::byte> expected_output;
};

struct NISTTestMonteSample {
  std::uint32_t i = 0;
  std::vector<std::byte> M = {};
  std::vector<std::byte> Mdi = {};
};

struct NISTTestMonteStage {
  std::vector<NISTTestMonteSample> sample = {};
  std::vector<std::byte> MD = {};
};

struct NISTTestMonteVector {
  std::vector<std::byte> seed = {};
  std::vector<NISTTestMonteStage> stage = {};
};

std::vector<NISTTestVector> ParseMsg(const std::filesystem::path& file_path);
NISTTestMonteVector ParseMonte(const std::filesystem::path& file_path);

}  // namespace file_encrypt::util::NISTTestVectorParser

#endif