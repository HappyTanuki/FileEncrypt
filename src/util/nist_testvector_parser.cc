#include "util/nist_testvector_parser.h"

#include <fstream>
#include <regex>

#include "util/helper.h"

namespace file_encrypt::util::NISTTestVectorParser {

std::vector<NISTTestVector> ParseMsg(const std::filesystem::path& file_path) {
  std::vector<NISTTestVector> test_vectors = {};
  std::vector<std::uint64_t> Len = {};
  std::vector<std::vector<std::byte>> Msg = {};
  std::vector<std::vector<std::byte>> MD = {};

  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size("\\[\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*");

  if (!file.is_open()) {
    NISTTestVector error_message = {{}, 0, StrToBytes("Error opening file.")};
    test_vectors.push_back(error_message);
    return test_vectors;
  }
  while (std::getline(file, line)) {
    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
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

  if (Len.size() != Msg.size() || Len.size() != MD.size()) {
    NISTTestVector error_message = {{}, 0, StrToBytes("Error parsing file.")};
    test_vectors.push_back(error_message);
    return test_vectors;
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

  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size("\\[\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*");
  std::regex variable_indented("\\s+([a-zA-Z0-9]+)\\s*=\\s*([a-fA-F0-9]+)\\s*");

  NISTTestMonteSample sample;
  std::queue<NISTTestMonteSample> samples = {};
  std::uint32_t count = 0;

  if (!file.is_open()) {
    monte_vector.return_code = ReturnStatusCode::kError;
    monte_vector.seed = StrToBytes("Error opening file.");
    return monte_vector;
  }

  while (std::getline(file, line)) {
    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (std::regex_match(line, matches, variable_indented)) {
      std::string var_name = matches[1];
      std::string var_value = matches[2];

      if (var_name == "i") {
        sample.i = std::stoul(var_value, nullptr, 10);
      } else if (var_name == "M") {
        sample.M = HexStringToBytes(var_value);
      } else if (var_name == "MDi") {
        sample.MDi = HexStringToBytes(var_value);
      }
      if (sample.i != 0 && !sample.M.empty() && !sample.MDi.empty()) {
        samples.push(sample);
        sample = NISTTestMonteSample();
      }
      continue;
    }

    if (!std::regex_match(line, matches, variable)) {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (var_name == "Seed") {
      monte_vector.seed = HexStringToBytes(var_value);
    } else if (var_name == "COUNT") {
      count = std::stoul(var_value, nullptr, 10);
    } else if (var_name == "MD") {
      NISTTestMonteStage stage;
      stage.count = count;
      stage.samples = samples;
      monte_vector.MD.push_back(HexStringToBytes(var_value));
      monte_vector.stage.push_back(stage);
      samples = {};
      count = 0;
    }
  }

  monte_vector.return_code = ReturnStatusCode::kSuccess;

  return monte_vector;
}

}  // namespace file_encrypt::util::NISTTestVectorParser
