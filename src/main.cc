#include <fstream>
#include <iostream>

#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "nolibc/getopt.h"
#include "util/helper.h"

namespace file_encrypt {

int main(int argc, char* argv[]) {
  int opt;
  std::string password;

  std::istream* input = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ofstream output_file;

  algorithm::op_mode::CipherMode cipher_mode =
      algorithm::op_mode::CipherMode::Encrypt;

  while ((opt = nolibc::getopt(argc, argv, "a:i:o:p:ed")) != -1) {
    switch (opt) {
      case 'i':
        if (nolibc::optarg[0] != '-') {
          input_file = std::ifstream(nolibc::optarg, std::ios::binary);
          input = &input_file;
        }
        break;
      case 'o':
        if (nolibc::optarg[0] != '-') {
          output_file = std::ofstream(nolibc::optarg, std::ios::binary);
          output = &output_file;
        }
        break;
      case 'p':
        password = nolibc::optarg;
        break;
      case 'e':
        cipher_mode = algorithm::op_mode::CipherMode::Encrypt;
        break;
      case 'd':
        cipher_mode = algorithm::op_mode::CipherMode::Decrypt;
        break;
      default: /* '?' */
        std::cerr << "Usage: " << argv[0] << "\n"
                  << " -a algorithm\n"
                     " -i input_file_or_phrase\n"
                     " -o output_file_or_stream\n"
                     " -k key\n"
                     "[-e / -d] (-e encrypt, -d decrypt)\n";
        std::exit(EXIT_FAILURE);
    }
  }

  algorithm::DRBG_SHA256 drbg;
  drbg.Instantiate(256, false);
  std::array<std::byte, 32> key;
  std::array<std::byte, 16> iv;

  if (cipher_mode == algorithm::op_mode::CipherMode::Encrypt) {
    auto key_return = drbg.Generate(256, 256, false, {});
    auto iv_return = drbg.Generate(128, 256, false, {});
    if (key_return.status != algorithm::CSPRNG::ReturnStatus::kSUCCESS ||
        iv_return.status != algorithm::CSPRNG::ReturnStatus::kSUCCESS) {
      std::cerr << "CSPRNG error\n";
      std::exit(EXIT_FAILURE);
    }
    std::memcpy(key.data(), key_return.pseudorandom_bits.data(), 32);
    std::memcpy(iv.data(), iv_return.pseudorandom_bits.data(), 16);
  } else {
    std::vector<std::byte> password_bytes = util::HexStrToBytes(password);
    std::memcpy(key.data(), password_bytes.data(), 32);
    std::memcpy(iv.data(), password_bytes.data() + 32, 16);
  }

  algorithm::AES_256_CBC<1> aes_cbc(key, iv);
  aes_cbc << cipher_mode;

  while (input->good()) {
    std::array<std::byte, 16> buffer = {};
    input->read(reinterpret_cast<char*>(buffer.data()), 16);
    std::streamsize read_bytes = input->gcount();
    if (read_bytes == 0) break;

    std::vector<std::byte> data(buffer.begin(), buffer.begin() + read_bytes);
    aes_cbc << data;

    algorithm::op_mode::OperationModeOutputData<128> output_data;
    aes_cbc >> output_data;

    output->write(reinterpret_cast<char*>(output_data.data.data()),
                  output_data.data.size());
  }

  std::cout << "Password: "
            << util::BytesToHexStr(key) + util::BytesToHexStr(iv) << std::endl;

  std::exit(EXIT_SUCCESS);
}

}  // namespace file_encrypt

int main(int argc, char* argv[]) { return file_encrypt::main(argc, argv); }