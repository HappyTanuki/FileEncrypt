#include <fstream>
#include <iostream>

#include "algorithm/base64.h"
#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "algorithm/padding/pkcs_7.h"
#include "nolibc/getopt.h"
#include "util/helper.h"

namespace file_encrypt {

int main(int argc, char* argv[]) {
  int opt;
  std::string key_hex;

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
        key_hex = nolibc::optarg;
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
                     " -h digests file\n"
                     "[-e / -d] (-e encrypt, -d decrypt / compare digest in "
                     "hash mode)\n";
        std::exit(EXIT_FAILURE);
    }
  }

  algorithm::BASE64 base64;
  algorithm::DRBG_SHA256 drbg;
  drbg.Instantiate(256, false);
  algorithm::Pkcs_7<128> pkcs_7;
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
    output->write(reinterpret_cast<char*>(iv.data()), 16);
  } else {
    std::vector<std::byte> password_bytes =
        base64.Decoding(base64.ReplaceChar(util::StrToBytes(key_hex)));
    std::memcpy(key.data(), password_bytes.data(), 32);
    input->read(reinterpret_cast<char*>(iv.data()), 16);
  }

  algorithm::AES_CBC<256> aes_cbc(key, iv);
  aes_cbc << cipher_mode;

  while (input->good()) {
    std::array<std::byte, 16> buffer = {};
    input->read(reinterpret_cast<char*>(buffer.data()), 16);
    std::streamsize read_bytes = input->gcount();
    size_t write_size = 0;
    if (read_bytes == 0) break;

    std::vector<std::byte> data(buffer.begin(), buffer.begin() + read_bytes);

    if (input->peek() == EOF) {
      if (cipher_mode == algorithm::op_mode::CipherMode::Encrypt) {
        auto padded = pkcs_7.MakePaddingBlock(data).back();
        data.resize(16);
        std::memcpy(data.data(), padded.data(), padded.size());
      }
    }

    aes_cbc << data;

    algorithm::op_mode::OperationModeOutputData<128> output_data;
    aes_cbc >> output_data;

    write_size = output_data.data.size();
    if (input->peek() == EOF) {
      if (cipher_mode == algorithm::op_mode::CipherMode::Decrypt) {
        auto un_padded = pkcs_7.RemovePadding(
            {output_data.data.begin(), output_data.data.end()});
        std::memcpy(output_data.data.data(), un_padded.data.data(),
                    un_padded.data.size());
        write_size = un_padded.real_length;
      }
    }

    output->write(reinterpret_cast<char*>(output_data.data.data()), write_size);
  }

  if (cipher_mode == algorithm::op_mode::CipherMode::Encrypt) {
    std::cout << "Key: "
              << util::BytesToStr(base64.Encoding({key.begin(), key.end()}))
              << std::endl;
  }

  output->flush();

  std::exit(EXIT_SUCCESS);
}

}  // namespace file_encrypt

int main(int argc, char* argv[]) { return file_encrypt::main(argc, argv); }