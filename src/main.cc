#include <fstream>
#include <iostream>

#define CXXOPTS_NO_EXCEPTIONS
#define PROGRAM_DESCRIPTION \
  "A file encryption, decryption, and hash validation utility."

#include "algorithm/base64.h"
#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "algorithm/padding/pkcs_7.h"
#include "cxxopts.hpp"
#include "util/helper.h"

namespace file_encrypt {

cxxopts::ParseResult ToplevelArgParse(int argc, char* argv[],
                                      std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options("Mode")("Mode",
                              "\"encrypt\"\tEncryption mode.\n"
                              "\"decrypt\"\tDecryption mode.\n"
                              "\"hash\"\tHashing digest or compare mode.\n"
                              "\"keygen\"\tKeygen mode.",
                              cxxopts::value<std::string>());
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")("overwrite",
                                 "Overwrite output file if exists");

  options.show_positional_help();

  options.parse_positional({"Mode"});
  options.custom_help("(encrypt|decrypt|hash|keygen)");
  options.positional_help("[OPTION...]");
  options.allow_unrecognised_options();

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult EncryptArgParse(int argc, char* argv[],
                                     std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()("a,algorithm", "Algorithm to use (example:AES-256-CBC)",
                        cxxopts::value<std::string>());
  options.add_options()(
      "k,key", "<file|text|-> key file, BASE64 encoded text, or '-' for prompt",
      cxxopts::value<std::string>());
  options.add_options()(
      "i,input", "<file|text|-> Input source: file, message, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options()("p,password",
                        "[file|text|-] password file, text, or '-' for prompt",
                        cxxopts::value<std::string>());
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)");

  options.allow_unrecognised_options();
  options.custom_help("encrypt [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult DecryptArgParse(int argc, char* argv[],
                                     std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()("a,algorithm", "Algorithm to use (example:AES-256-CBC)",
                        cxxopts::value<std::string>());
  options.add_options()(
      "k,key", "<file|text|-> key file, BASE64 encoded text, or '-' for prompt",
      cxxopts::value<std::string>());
  options.add_options()(
      "i,input",
      "<file|text|-> Input source: file, cipher text, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options()("p,password",
                        "[file|text|-] password file, text or '-' for prompt",
                        cxxopts::value<std::string>());
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)");

  options.allow_unrecognised_options();
  options.custom_help("decrypt [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult HashArgParse(int argc, char* argv[],
                                  std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()("a,algorithm", "Algorithm to use (example:SHA-256)",
                        cxxopts::value<std::string>());
  options.add_options()(
      "diff",
      "<fileA>,<fileB> Compare two files by hash (when this option is "
      "specified, the -i, -o options do not need to specified).",
      cxxopts::value<std::vector<std::string>>());
  options.add_options()(
      "i,input", "<file|text|-> Input source: file, text, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)");

  options.allow_unrecognised_options();
  options.custom_help("hash [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

int main(int argc, char* argv[]) {
  int opt;
  std::string key_hex;

  std::istream* input = &std::cin;
  std::istream* password = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ifstream password_file;
  std::ofstream output_file;

  algorithm::op_mode::CipherMode cipher_mode =
      algorithm::op_mode::CipherMode::Encrypt;

  std::string help_string;
  auto parsed_args = ToplevelArgParse(argc, argv, help_string);

  if (parsed_args.count("help")) {
    std::cout << help_string << std::endl;
    return 0;
  }

  if (parsed_args.count("Mode") != 0) {
    std::string mode_name = parsed_args["Mode"].as<std::string>();
    if (mode_name != "encrypt" && mode_name != "decrypt" &&
        mode_name != "hash" && mode_name != "keygen") {
      std::cerr << help_string << std::endl;
      return -1;
    }
  } else {
    std::cerr << "A mode shall always be specified." << std::endl;
    return -1;
  }

  if (parsed_args["Mode"].as<std::string>() == "encrypt") {
    cipher_mode = algorithm::op_mode::CipherMode::Encrypt;
    parsed_args = EncryptArgParse(argc, argv, help_string);

    if (!parsed_args.unmatched().empty()) {
      std::cerr << help_string << std::endl;
      return -1;
    } else if (parsed_args.count("help")) {
      std::cout << help_string << std::endl;
      return 0;
    }
  } else if (parsed_args["Mode"].as<std::string>() == "decrypt") {
    cipher_mode = algorithm::op_mode::CipherMode::Decrypt;
    parsed_args = DecryptArgParse(argc, argv, help_string);

    if (!parsed_args.unmatched().empty()) {
      std::cerr << help_string << std::endl;
      return -1;
    } else if (parsed_args.count("help")) {
      std::cout << help_string << std::endl;
      return 0;
    }
  } else if (parsed_args["Mode"].as<std::string>() == "hash") {
    parsed_args = HashArgParse(argc, argv, help_string);

    if (!parsed_args.unmatched().empty()) {
      std::cerr << help_string << std::endl;
      return -1;
    } else if (parsed_args.count("help")) {
      std::cout << help_string << std::endl;
      return 0;
    }
  }

  // mode_option_adder("encrypt", "Encryption mode.");
  // mode_option_adder("decrypt", "Decryption mode.");
  // mode_option_adder("hash", "Hashing digest or compare mode.");
  // mode_option_adder("keygen", "Keygen mode.");
  // option_adder("a,algorithm", "Algorithm to use (example:AES-256-CBC)",
  //              cxxopts::value<std::string>());
  // option_adder("i,input",
  //              "<file|text|-> Input source: file, raw text, or '-' for
  //              stdin", cxxopts::value<std::string>());
  // option_adder("o,output", "<file|-> Output file or '-' for stdout",
  //              cxxopts::value<std::string>());
  // option_adder("k,key",
  //              "<file|text|-> key file, BASE64 encoded text, or '-' for
  //              stdin", cxxopts::value<std::string>());
  // option_adder("g,genkey", "Generate random key and save to output");
  // option_adder("p,password",
  //              "[prompt|file] Derive key from password (prompt or file)",
  //              cxxopts::value<std::string>());
  // option_adder("h,hash", "<file> Hash output or comparison target",
  //              cxxopts::value<std::string>());
  // option_adder("diff", "<fileA>,<fileB> Compare two files by hash",
  //              cxxopts::value<std::vector<std::string>>());
  // option_adder("overwrite", "Overwrite output file if exists");

  if (parsed_args.count("mode") == 0) {
    std::cerr << "A mode shall always be specified." << std::endl;
    return -1;
  }

  if (parsed_args.count("algorithm") == 0) {
    std::cerr << "An algorithm name shall always be specified." << std::endl;
    return -1;
  }

  if (parsed_args.count("output") == 0) {
    std::cerr << "An output shall always be specified." << std::endl;
    return -1;
  }

  std::string input_filename = parsed_args["input"].as<std::string>();
  if (input_filename != "-") {
    input_file = std::ifstream(input_filename, std::ios::binary);
    input = &input_file;
  }
  std::string output_filename = parsed_args["output"].as<std::string>();
  if (output_filename != "-") {
    output_file = std::ofstream(output_filename, std::ios::binary);
    output = &output_file;
  }

  // while ((opt = nolibc::getopt(argc, argv, "a:i:o:p:ed")) != -1) {
  //   switch (opt) {
  //     case 'i':
  //       if (nolibc::optarg[0] != '-') {
  //         input_file = std::ifstream(nolibc::optarg, std::ios::binary);
  //         input = &input_file;
  //       }
  //       break;
  //     case 'o':
  //       if (nolibc::optarg[0] != '-') {
  //         output_file = std::ofstream(nolibc::optarg, std::ios::binary);
  //         output = &output_file;
  //       }
  //       break;
  //     case 'p':
  //       key_hex = nolibc::optarg;
  //       break;
  //     case 'e':
  //       cipher_mode = algorithm::op_mode::CipherMode::Encrypt;
  //       break;
  //     case 'd':
  //       cipher_mode = algorithm::op_mode::CipherMode::Decrypt;
  //       break;
  //     default: /* '?' */
  //       std::cerr
  //           << "Usage:\n"
  //              "\t"
  //           << argv[0]
  //           << "<mode> [options]\n\n"
  //              "Modes:\n"
  //              "\tencrypt, decrypt File or stream
  //              encryption/decryption\n"
  //              "\thash             Generate or verify a hash"
  //              "\tdiff             Compare two files by hash"
  //              "Common Options:\n"
  //              "\t-a, --algorithm <name> Algorithm to use (default: "
  //              "AES-256-cbc)\n"
  //              "\t-i, --input <file|text|-> Input source: file, raw text,
  //              " "or '-' for stdin\n"
  //              "\t-o, --output <file|-> Output file or '-' for stdout\n"
  //              "\t-k, --key <file> Use an existing key file\n"
  //              "\t-g, --genkey <file> Generate random key and save to
  //              file\n"
  //              "\t-p, --password [prompt|file] Derive key from password "
  //              "(prompt or file)\n"
  //              "\t-h, --hash <file> Hash output or comparison target\n"
  //              "\t--diff <fileA> <fileB> Compare two files by hash\n"
  //              "\t--overwrite Overwrite output file if exists\n"
  //              "\t-H, --help Show this help message\n";
  //       std::exit(EXIT_FAILURE);
  //   }
  // }

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

  std::cout << "processing complete.";

  std::exit(EXIT_SUCCESS);
}

}  // namespace file_encrypt

int main(int argc, char* argv[]) { return file_encrypt::main(argc, argv); }