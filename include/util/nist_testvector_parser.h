#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_NIST_TESTVECTOR_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "algorithm/algorithm.h"

namespace file_encrypt::util::NISTTestVectorParser {

enum class ReturnStatusCode { kSuccess = 0, kError = -1 };
enum class VectorCategory { kEncrypt = 0, kDecrypt = 1 };

struct NISTTestVariables {
  std::unordered_map<std::string, std::int32_t> intager = {};
  std::unordered_map<std::string, std::vector<std::byte>> binary = {};
};

struct NISTTestMonteSample {
  NISTTestVariables variable = {};
};

struct NISTTestMonteData {
  std::queue<NISTTestMonteSample> samples = {};
  NISTTestVariables variable = {};
};

ReturnStatusCode ParseHashVector(const std::filesystem::path& file_path,
                                 std::vector<NISTTestVariables>& test_vectors);
ReturnStatusCode ParseHashMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteData>& test_vectors);

ReturnStatusCode ParseCipherVector(const std::filesystem::path& file_path,
                                   std::vector<NISTTestVariables>& test_vectors,
                                   VectorCategory category);
ReturnStatusCode ParseCipherMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteData>& test_vectors, VectorCategory category);

}  // namespace file_encrypt::util::NISTTestVectorParser

#endif