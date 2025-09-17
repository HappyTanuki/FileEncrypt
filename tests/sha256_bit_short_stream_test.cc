#include "algorithm/sha256.h"
#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

int main() {
  file_encrypt::algorithm::SHA256 sha256;

  std::vector<NISTTestVectorParser::NISTTestVector> test_vectors =
      NISTTestVectorParser::ParseMsg("./shabittestvectors/SHA256ShortMsg.rsp");
  if (test_vectors.back().Len == 0 && test_vectors.back().Msg.size() == 0) {
    std::string err_string(
        reinterpret_cast<const char*>(test_vectors.back().MD.data()),
        test_vectors.back().MD.size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << "SHA-256 Bit-Oriented ShortMsg stream test: " << std::endl;
  for (NISTTestVectorParser::NISTTestVector item : test_vectors) {
    std::cout << "Len: " << std::dec << item.Len << "\n";
    std::cout << "Msg: 0x";
    for (auto byte : item.Msg) {
      std::cout << std::hex << std::to_integer<int>(byte);
    }
    std::cout << "\n";

    if (item.Len == 505) {
      std::cout << "test vector (Len=505)" << std::endl;
    }

    file_encrypt::algorithm::HashAlgorithmInputData input_data;
    input_data.bit_length = item.Len;
    input_data.message = item.Msg;

    // 메시지를 절반으로 나누기
    size_t mid_bytes = (item.Len / 8) / 2;

    file_encrypt::algorithm::HashAlgorithmInputData part1;
    part1.bit_length = mid_bytes * 8;
    part1.message = std::vector<std::byte>(
        input_data.message.begin(), input_data.message.begin() + mid_bytes);

    file_encrypt::algorithm::HashAlgorithmInputData part2;
    part2.bit_length = input_data.bit_length - part1.bit_length;
    part2.message = std::vector<std::byte>(
        input_data.message.begin() + mid_bytes, input_data.message.end());

    // SHA256 업데이트
    sha256.Update(part1);
    sha256.Update(part2);
    file_encrypt::algorithm::HashAlgorithmReturnData result = sha256.Digest();
    sha256.Reset();

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