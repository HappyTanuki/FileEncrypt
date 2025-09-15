#include "algorithm/sha256.h"

#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

int main() {
  file_encrypt::algorithm::SHA256 sha256;

  std::vector<NISTTestVectorParser::NISTTestVector> test_vectors =
      NISTTestVectorParser::ParseMsg("./shabytetestvectors/SHA256ShortMsg.rsp");
  if (test_vectors.back().Len == 0 && test_vectors.back().Msg.size() == 0) {
    std::string err_string(
        reinterpret_cast<const char*>(test_vectors.back().MD.data()),
        test_vectors.back().MD.size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << "SHA-256 ShortMsg test: " << std::endl;
  for (NISTTestVectorParser::NISTTestVector item : test_vectors) {
    std::cout << "Len: " << std::dec << item.Len << "\n";
    std::cout << "Msg: 0x";
    for (auto byte : item.Msg) {
      std::cout << std::hex << std::to_integer<int>(byte);
    }
    std::cout << "\n";

    file_encrypt::algorithm::HashAlgorithmInputData input_data;
    input_data.bit_length = item.Len;
    input_data.message = item.Msg;

    file_encrypt::algorithm::HashAlgorithmReturnData result =
        sha256.Digest(input_data);

    std::cout << "MD: 0x";
    for (int i = 0; i < 32; i++) {
      std::cout << std::hex << std::to_integer<int>(result.digest[i]);
    }
    std::cout << "\n";

    std::cout << "Match: ";
    if (result.digest == item.MD) {
      std::cout << "True" << std::endl;
    } else {
      std::cout << "False" << std::endl;
      return -1;
    }
  }

  return 0;
}