#include "algorithm/sha256.h"
#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = file_encrypt::util::NISTTestVectorParser;

static std::vector<std::byte> ByteStitch(const std::vector<std::byte>& a,
                                         const std::vector<std::byte>& b,
                                         const std::vector<std::byte>& c) {
  std::vector<std::byte> result;
  result.reserve(a.size() + b.size() + c.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result.push_back(a[i]);
  }
  for (size_t i = 0; i < b.size(); ++i) {
    result.push_back(b[i]);
  }
  for (size_t i = 0; i < c.size(); ++i) {
    result.push_back(c[i]);
  }
  return result;
}

int main() {
  file_encrypt::algorithm::SHA256 sha256;

  NISTTestVectorParser::NISTTestMonteVector test_vectors =
      NISTTestVectorParser::ParseMonte("./shabittestvectors/SHA256Monte.txt");
  if (test_vectors.return_code !=
      file_encrypt::algorithm::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(test_vectors.seed.data()),
        test_vectors.seed.size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::vector<std::byte> seed = test_vectors.seed;

  std::cout << "SHA-256 Monte-Carlo Bit-Oriented complex test: " << std::endl;
  for (NISTTestVectorParser::NISTTestMonteStage item : test_vectors.stage) {
    std::cout << "COUNT: " << std::dec << item.count << "\n";

    std::array<std::vector<std::byte>, 1003> MD;
    std::array<std::vector<std::byte>, 1003> M;
    MD[0] = seed;
    MD[1] = seed;
    MD[2] = seed;

    for (int i = 3; i < 1003; i++) {
      file_encrypt::algorithm::HashAlgorithmInputData message_input_data;
      message_input_data.bit_length = 256 * 3;
      M[i] = ByteStitch(MD[i - 3], MD[i - 2], MD[i - 1]);
      message_input_data.message = M[i];
      auto ret_value = sha256.Digest(message_input_data);
      MD[i] = ret_value.digest;

      if (!item.samples.empty() && item.samples.front().i == i) {
        file_encrypt::util::NISTTestVectorParser::NISTTestMonteSample sample =
            item.samples.front();
        item.samples.pop();
        std::cout << "  i: " << std::dec << sample.i << "\n";
        std::cout << "  M: 0x";
        for (auto byte : sample.M) {
          std::cout << std::hex << std::to_integer<int>(byte);
        }
        std::cout << "\n";
        std::cout << "  MDi: 0x";
        for (auto byte : sample.MDi) {
          std::cout << std::hex << std::to_integer<int>(byte);
        }
        std::cout << "\n";

        if (sample.M != M[i]) {
          std::cout << "Mismatch M" << std::endl;
          std::cout << "Computed M: 0x";
          for (auto byte : M[i]) {
            std::cout << std::hex << std::to_integer<int>(byte);
          }
          std::cout << "\n";
          return -1;
        }
        if (sample.MDi != MD[i]) {
          std::cout << "Mismatch MDi" << std::endl;
          std::cout << "Computed MDi: 0x";
          for (auto byte : MD[i]) {
            std::cout << std::hex << std::to_integer<int>(byte);
          }
          std::cout << "\n";
          return -1;
        }
      }
    }

    MD[item.count] = MD[1002];
    seed = MD[1002];

    std::cout << "MD: 0x";
    for (int i = 0; i < 32; i++) {
      std::cout << std::hex
                << std::to_integer<int>(test_vectors.MD[item.count][i]);
    }
    std::cout << "\n";

    std::cout << "Match: ";
    if (seed == test_vectors.MD[item.count]) {
      std::cout << "True" << std::endl;
    } else {
      std::cout << "False" << std::endl;
      return -1;
    }
  }

  return 0;
}