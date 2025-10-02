#include "algorithm/sha256.h"
#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

int main() {
  file_encrypt::algorithm::SHA256 sha256;

  std::vector<NISTTestVectorParser::NISTTestVariables> test_vectors;
  if (NISTTestVectorParser::ParseHashVector(
          "./tests/test_vector/shabytetestvectors/SHA256ShortMsg.rsp",
          test_vectors) != NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(reinterpret_cast<const char*>(
                               test_vectors.back().binary["error_msg"].data()),
                           test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << "SHA-256 Byte-Oriented ShortMsg test: " << std::endl;
  for (NISTTestVectorParser::NISTTestVariables item : test_vectors) {
    std::cout << "Len: " << std::dec << item.intager["Len"] << "\n";
    std::cout << "Msg: 0x";
    for (auto byte : item.binary["Msg"]) {
      std::cout << std::hex << std::to_integer<int>(byte);
    }
    std::cout << "\n";

    file_encrypt::algorithm::HashAlgorithmInputData input_data;
    input_data.bit_length = item.intager["Len"];
    input_data.message = item.binary["Msg"];

    file_encrypt::algorithm::HashAlgorithmReturnData result =
        sha256.Digest(input_data);

    std::cout << "MD: 0x";
    for (int i = 0; i < 32; i++) {
      std::cout << std::hex << std::to_integer<int>(result.digest[i]);
    }
    std::cout << "\n";

    std::cout << "Match: ";
    if (result.digest == item.binary["MD"]) {
      std::cout << "True" << std::endl;
    } else {
      std::cout << "False" << std::endl;
      return -1;
    }
  }

  return 0;
}