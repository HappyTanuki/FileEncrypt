#include "util/nist_testvector_parser.h"

#include <fstream>
#include <regex>

#include "util/helper.h"

namespace file_encrypt::util::NISTTestVectorParser {

ReturnStatusCode ParseHashVector(const std::filesystem::path& file_path,
                                 std::vector<NISTTestVariables>& test_vectors) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");

  if (!file.is_open()) {
    NISTTestVariables error_object;
    error_object.binary["error_msg"] = StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  int count = 0;

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestVariables());
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

    if (var_name == "Len" ||
        std::regex_match(var_name, std::regex(".*COUNT.*"))) {
      if (test_vectors[count].intager.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].intager[var_name] =
          std::stoul(var_value, nullptr, 10);
    } else {
      if (test_vectors[count].binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].binary[var_name] = HexStringToBytes(var_value);
    }
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseHashMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex variable_indented(
      "\\s+([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");

  NISTTestMonteSample sample;
  std::queue<NISTTestMonteSample> samples = {};
  std::uint32_t count = 0;
  bool indented = false;
  bool pre_indented = false;

  if (!file.is_open()) {
    NISTTestMonteStage error_object;
    error_object.variable.binary["error_msg"] =
        StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestMonteStage());
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
      indented = true;
    } else if (std::regex_match(line, matches, variable)) {
      indented = false;
    } else {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (indented) {
      if (var_name == "i" ||
          std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        if (sample.variable.intager.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.intager.clear();
          sample.variable.binary.clear();
        }
        sample.variable.intager[var_name] = std::stoul(var_value, nullptr, 10);
      } else {
        if (sample.variable.binary.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.intager.clear();
          sample.variable.binary.clear();
        }
        sample.variable.binary[var_name] = HexStringToBytes(var_value);
      }
    } else {
      if (pre_indented) {
        test_vectors[count].samples.push(sample);
        sample.variable.intager.clear();
        sample.variable.binary.clear();
      }

      if (test_vectors[count].variable.intager.contains(var_name) ||
          test_vectors[count].variable.binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestMonteStage());
      }
      if (std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        test_vectors[count].variable.intager[var_name] =
            std::stoul(var_value, nullptr, 10);
      } else {
        test_vectors[count].variable.binary[var_name] =
            HexStringToBytes(var_value);
      }
    }

    pre_indented = indented;
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseCipherVector(const std::filesystem::path& file_path,
                                   std::vector<NISTTestVariables>& test_vectors,
                                   VectorCategory category) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex encrypt("\\[ENCRYPT\\]");
  std::regex decrypt("\\[DECRYPT\\]");
  bool reading = false;

  if (!file.is_open()) {
    NISTTestVariables error_object;
    error_object.binary["error_msg"] = StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  int count = 0;

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestVariables());
  }

  while (std::getline(file, line)) {
    if (category == VectorCategory::kEncrypt &&
        std::regex_search(line, encrypt)) {
      reading = true;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, decrypt)) {
      reading = true;
    } else if (category == VectorCategory::kEncrypt &&
               std::regex_search(line, decrypt)) {
      reading = false;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, encrypt)) {
      reading = false;
    }

    if (!reading) {
      continue;
    }

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

    if (var_name == "Len" ||
        std::regex_match(var_name, std::regex(".*COUNT.*"))) {
      if (test_vectors[count].intager.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].intager[var_name] =
          std::stoul(var_value, nullptr, 10);
    } else {
      if (test_vectors[count].binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].binary[var_name] = HexStringToBytes(var_value);
    }
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseCipherMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors, VectorCategory category) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex variable_indented(
      "\\s+([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex encrypt("\\[ENCRYPT\\]");
  std::regex decrypt("\\[DECRYPT\\]");
  bool reading = false;

  NISTTestMonteSample sample;
  std::queue<NISTTestMonteSample> samples = {};
  std::uint32_t count = 0;
  bool indented = false;
  bool pre_indented = false;

  if (!file.is_open()) {
    NISTTestMonteStage error_object;
    error_object.variable.binary["error_msg"] =
        StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestMonteStage());
  }

  while (std::getline(file, line)) {
    if (category == VectorCategory::kEncrypt &&
        std::regex_search(line, encrypt)) {
      reading = true;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, decrypt)) {
      reading = true;
    } else if (category == VectorCategory::kEncrypt &&
               std::regex_search(line, decrypt)) {
      reading = false;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, encrypt)) {
      reading = false;
    }

    if (!reading) {
      continue;
    }

    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (std::regex_match(line, matches, variable_indented)) {
      indented = true;
    } else if (std::regex_match(line, matches, variable)) {
      indented = false;
    } else {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (indented) {
      if (var_name == "i" ||
          std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        if (sample.variable.intager.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.intager.clear();
          sample.variable.binary.clear();
        }
        sample.variable.intager[var_name] = std::stoul(var_value, nullptr, 10);
      } else {
        if (sample.variable.binary.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.intager.clear();
          sample.variable.binary.clear();
        }
        sample.variable.binary[var_name] = HexStringToBytes(var_value);
      }
    } else {
      if (pre_indented) {
        test_vectors[count].samples.push(sample);
        sample.variable.intager.clear();
        sample.variable.binary.clear();
      }

      if (test_vectors[count].variable.intager.contains(var_name) ||
          test_vectors[count].variable.binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestMonteStage());
      }
      if (std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        test_vectors[count].variable.intager[var_name] =
            std::stoul(var_value, nullptr, 10);
      } else {
        test_vectors[count].variable.binary[var_name] =
            HexStringToBytes(var_value);
      }
    }

    pre_indented = indented;
  }

  return ReturnStatusCode::kSuccess;
}

}  // namespace file_encrypt::util::NISTTestVectorParser
