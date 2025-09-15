#include "util/nist_testvector_parser.h"

namespace file_encrypt::util::NISTTestVectorParser {

std::vector<NISTTestVector> ParseMsg(const std::filesystem::path& file_path) {
  std::vector<NISTTestVector> test_vectors;

  // Implement your parsing logic here

  return test_vectors;
}

NISTTestMonteVector ParseMonte(const std::filesystem::path& file_path) {
  NISTTestMonteVector monte_vector;

  // Implement your parsing logic here

  return monte_vector;
}

}  // namespace file_encrypt::util::NISTTestVectorParser
