#include "util/nist_testvector_parser.h"

#include <fstream>
#include <regex>

namespace file_encrypt::util::NISTTestVectorParser {

static std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result;
  result.reserve(s.size());
  for (char c : s) result.push_back(static_cast<std::byte>(c));
  return result;
}

std::vector<std::byte> HexStringToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::vector<NISTTestVector> ParseMsg(const std::filesystem::path& file_path) {
  std::vector<NISTTestVector> test_vectors = {};
  std::vector<std::uint64_t> Len = {};
  std::vector<std::vector<std::byte>> Msg = {};
  std::vector<std::vector<std::byte>> MD = {};

  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex block_size("\\[\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*");

  if (!file.is_open()) {
    NISTTestVector error_message = {{},
        0,
        StrToBytes("Error opening file.")};
    test_vectors.push_back(error_message);
    return test_vectors;
  }
  while (std::getline(file, line)) {
    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, block_size)) {
      continue;
    }

    if (!std::regex_match(line, matches, variable)) {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (var_name == "Len") {
      Len.push_back(std::stoul(var_value, nullptr, 10));
    } else if (var_name == "Msg") {
      Msg.push_back(HexStringToBytes(var_value));
    } else if (var_name == "MD") {
      MD.push_back(HexStringToBytes(var_value));
    }
  }
  
  test_vectors.reserve(Len.size());
  for (int i = 0; i < Len.size(); i++) {
    NISTTestVector item = {Msg[i], Len[i], MD[i]};
    test_vectors.push_back(item);
    
  }

  return test_vectors;
}

NISTTestMonteVector ParseMonte(const std::filesystem::path& file_path) {
  NISTTestMonteVector monte_vector;

  // Implement your parsing logic here

  return monte_vector;
}

}  // namespace file_encrypt::util::NISTTestVectorParser
