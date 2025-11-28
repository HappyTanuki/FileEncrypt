#include <fstream>
#include <iostream>
#include <sstream>

#define CXXOPTS_NO_EXCEPTIONS
#define PROGRAM_DESCRIPTION \
  "A file encryption, decryption, and hash validation utility."

#include "algorithm/base64.h"
#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/block_cipher/mode/block_cipher_modes_factory.h"
#include "algorithm/csprng/drbg_sha256.h"
#include "algorithm/padding/pkcs_7.h"
#include "algorithm/pbkdf2.h"
#include "cxxopts.hpp"
#include "util/arg_parser.h"
#include "util/echo_off.h"
#include "util/helper.h"
#include "util/key_loader.h"
#include "util/magic_number.h"

namespace file_encrypt {

enum class ProgramOperationMode { kError, kEncrypt, kDecrypt, kHash, kKeygen };

std::string PromptPasswordCreateInput() {
  std::string password;
  std::string password_confirm;

  util::EchoOff echo_off;

  while (true) {
    std::cout << "Enter password: ";
    std::cin >> password;
    std::cout << std::endl;
    std::cout << "Confirm password: ";
    std::cin >> password_confirm;
    std::cout << std::endl;
    if (password != password_confirm) {
      std::cout << "Passwords do not match." << std::endl;
      continue;
    }
    if (!password.empty()) break;
  }

  return password;
}

std::string PromptPasswordInput() {
  std::string password;

  util::EchoOff echo_off;

  while (true) {
    std::cout << "Enter password: ";
    std::cin >> password;
    if (!password.empty()) break;
  }

  return password;
}

template <std::uint32_t KeySize>
int EncryptMain(cxxopts::ParseResult parsed_args, std::string help_string) {
  std::istream* input = &std::cin;
  std::istream* key_input = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ifstream key_file;
  std::ofstream output_file;

  std::istringstream input_sstream;
  std::istringstream key_sstream;
  std::ostringstream output_sstream;

  algorithm::DRBG_SHA256 drbg;
  drbg.Instantiate(KeySize, false);

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();

  std::string password = "";
  bool use_password = false;
  bool use_key = true;
  if (parsed_args.count("use-password-only") > 0) {
    use_password = true;
    use_key = false;
  }

  if (parsed_args.count("password") > 0) {
    use_password = true;
    password = parsed_args["password"].as<std::string>();
    if (password == "-") password = PromptPasswordCreateInput();
  } else if (use_password && !use_key) {
    password = PromptPasswordCreateInput();
  }

  // 최종적으로 사용할 키
  std::array<std::byte, KeySize / 8> key = {};
  // 만약 엔트로피 추가용 랜덤 키를 쓴다면 여기에 저장됨
  // use_password && use_key일 때는 비밀번호 + 엔트로피 복합모드,
  // use_password && !use_key일 때는 비밀번호 전용모드,
  // !use_password && use_key일 때는 엔트로피 전용모드이기 때문에 이 키는 비어
  // 있음.
  std::array<std::byte, KeySize / 8> second_key = {};
  std::array<std::byte, 16> iv = {};
  std::vector<std::byte> salt = {};

  std::shared_ptr<file_encrypt::algorithm::HMAC> hmac =
      std::make_shared<file_encrypt::algorithm::HMAC>(
          std::make_unique<file_encrypt::algorithm::SHA256>());

  auto salt_return = drbg.Generate(KeySize, KeySize, false, {});
  if (salt_return.status != algorithm::ReturnStatus::kSUCCESS) {
    std::cerr << "CSPRNG error.\n";
    std::exit(EXIT_FAILURE);
  }
  salt = std::move(salt_return.pseudorandom_bits);

  auto iv_return = drbg.Generate(128, KeySize, false, {});
  if (iv_return.status != algorithm::ReturnStatus::kSUCCESS) {
    std::cerr << "CSPRNG error.\n";
    std::exit(EXIT_FAILURE);
  }
  std::memcpy(iv.data(), iv_return.pseudorandom_bits.data(), 16);

  if (!use_password && use_key && parsed_args.count("key") > 0) {
    // 키 입력이 있고 엔트로피 전용모드일 때
    use_key = true;
    std::string key_filename = parsed_args["key"].as<std::string>();
    if (key_filename != "-") {
      key_file = std::ifstream(key_filename, std::ios::binary);
      if (key_file.good()) {
        key_input = &key_file;
      } else {
        key_sstream = std::istringstream(key_filename);
        key_input = &key_sstream;
      }
    }
    key = util::KeyLoad<KeySize>(key_input, algorithm_name);
  } else if (use_password && !use_key) {
    // 비밀번호 전용모드일 때
    key = algorithm::PBKDF2<KeySize>(password, salt, hmac, 600000);
  } else if (use_password && use_key) {
    // 비밀번호 엔트로피 복합모드일 때
    key = algorithm::PBKDF2<KeySize>(password, salt, hmac, 600000);
    auto key_return = drbg.Generate(KeySize, KeySize, false, {});
    if (key_return.status != algorithm::ReturnStatus::kSUCCESS) {
      std::cerr << "CSPRNG error.\n";
      std::exit(EXIT_FAILURE);
    }
    std::memcpy(second_key.data(), key_return.pseudorandom_bits.data(),
                KeySize / 8);
  } else {
    // 키 입력이 없고 엔트로피 전용모드일 때
    auto key_return = drbg.Generate(KeySize, KeySize, false, {});
    if (key_return.status != algorithm::ReturnStatus::kSUCCESS) {
      std::cerr << "CSPRNG error.\n";
      std::exit(EXIT_FAILURE);
    }
    std::memcpy(key.data(), key_return.pseudorandom_bits.data(), KeySize / 8);
  }

  if (parsed_args.count("input") == 0) {
    std::cerr << "An input shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string input_filename = parsed_args["input"].as<std::string>();
  if (input_filename != "-") {
    input_file = std::ifstream(input_filename, std::ios::binary);
    if (input_file.good()) {
      input = &input_file;
    } else {
      input_sstream = std::istringstream(input_filename);
      input = &input_sstream;
    }
  }
  std::string output_filename = parsed_args["output"].as<std::string>();
  if (output_filename != "-") {
    if (std::filesystem::exists(output_filename) &&
        parsed_args.count("overwrite") == 0) {
      std::string prompt_input = "";
      std::cout << "Overwrite? [y/N]:";
      std::cin >> prompt_input;
      if (prompt_input == "Y" || prompt_input == "y") {
        output_file = std::ofstream(output_filename, std::ios::binary);
        output = &output_file;
      } else {
        std::cerr << "Exiting...\n";
        std::exit(EXIT_FAILURE);
      }
    } else {
      output_file = std::ofstream(output_filename, std::ios::binary);
      output = &output_file;
    }
  }

  algorithm::BASE64 base64;
  algorithm::Pkcs_7<128> pkcs_7;
  if (use_password && use_key)
    output->write(
        reinterpret_cast<const char*>(util::PasswordCombinedKey.data()), 4);
  else if (use_password && !use_key)
    output->write(reinterpret_cast<const char*>(util::PasswordOnlyKey.data()),
                  4);
  else
    output->write(reinterpret_cast<const char*>(util::NoPasswordKey.data()), 4);
  output->write(reinterpret_cast<char*>(iv.data()), 16);
  if (use_password)
    output->write(reinterpret_cast<char*>(salt.data()), KeySize / 8);

  std::ofstream temp_ofstream = std::ofstream("key.pem", std::ios::binary);
  if (use_key && !use_password) {
    // 엔트로피 키 전용모드
    util::KeyStore<KeySize>(static_cast<std::ostream*>(&temp_ofstream), key,
                            algorithm_name);
  } else if (use_key && use_password) {
    // 엔트로피 키 + 비밀번호 모드
    util::KeyStore<KeySize>(static_cast<std::ostream*>(&temp_ofstream),
                            second_key, algorithm_name);
  }
  // 비밀번호 전용모드는 키를 저장할 필요가 없음

  std::unique_ptr<algorithm::op_mode::OperationMode<128, KeySize, 1>>
      encrypt_algorithm = algorithm::op_mode::OPModeFactory<KeySize>(
          algorithm_name, util::XorArrays<KeySize / 8>(key, second_key), iv);
  *encrypt_algorithm << algorithm::op_mode::CipherMode::Encrypt;

  while (input->good()) {
    std::array<std::byte, 16> buffer = {};
    input->read(reinterpret_cast<char*>(buffer.data()), 16);
    std::streamsize read_bytes = input->gcount();
    size_t write_size = 0;
    if (read_bytes == 0) break;

    std::vector<std::byte> data(buffer.begin(), buffer.begin() + read_bytes);

    if (input->peek() == EOF) {
      auto padded = pkcs_7.MakePaddingBlock(data).back();
      data.resize(16);
      std::memcpy(data.data(), padded.data(), padded.size());
    }

    *encrypt_algorithm << data;

    algorithm::op_mode::OperationModeOutputData<128> output_data;
    *encrypt_algorithm >> output_data;

    write_size = output_data.data.size();

    output->write(reinterpret_cast<char*>(output_data.data.data()), write_size);
  }
  output->flush();

  std::exit(EXIT_SUCCESS);
}

template <std::uint32_t KeySize>
int DecryptMain(cxxopts::ParseResult parsed_args, std::string help_string) {
  std::istream* input = &std::cin;
  std::istream* key_input = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ifstream key_file;
  std::ofstream output_file;

  std::istringstream input_sstream;
  std::istringstream key_sstream;
  std::ostringstream output_sstream;

  std::array<std::byte, 4> magic_number;
  std::array<std::byte, KeySize / 8> key;
  std::array<std::byte, KeySize / 8> second_key = {};
  std::array<std::byte, 16> iv;
  std::vector<std::byte> salt(KeySize / 8);

  std::shared_ptr<file_encrypt::algorithm::HMAC> hmac =
      std::make_shared<file_encrypt::algorithm::HMAC>(
          std::make_unique<file_encrypt::algorithm::SHA256>());

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();

  if (parsed_args.count("input") == 0) {
    std::cerr << "An input shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string input_filename = parsed_args["input"].as<std::string>();
  if (input_filename != "-") {
    input_file = std::ifstream(input_filename, std::ios::binary);
    if (input_file.good()) {
      input = &input_file;
    } else {
      input_sstream = std::istringstream(input_filename);
      input = &input_sstream;
    }
  }

  // File header
  input->read(reinterpret_cast<char*>(magic_number.data()), 4);
  input->read(reinterpret_cast<char*>(iv.data()), 16);
  if (magic_number != util::NoPasswordKey)
    input->read(reinterpret_cast<char*>(salt.data()), KeySize / 8);

  std::string password = "";
  bool use_password = false;
  bool use_key = true;

  if (magic_number == util::PasswordCombinedKey ||
      magic_number == util::PasswordOnlyKey) {
    use_password = true;
    if (parsed_args.count("password") > 0) {
      password = parsed_args["password"].as<std::string>();
      if (password == "-") password = PromptPasswordInput();
    } else {
      password = PromptPasswordInput();
    }
    key = algorithm::PBKDF2<KeySize>(password, salt, hmac, 600000);
  } else if (magic_number == util::NoPasswordKey) {
    // Nothing to do
  } else {
    // Invalid
    std::cerr << "Unknown file format." << std::endl;
    std::exit(EXIT_FAILURE);
  }

  if ((magic_number == util::PasswordCombinedKey ||
       magic_number == util::NoPasswordKey) &&
      parsed_args.count("key") == 0) {
    std::cerr << "A key shall be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  if (parsed_args.count("key") > 0) {
    std::string key_filename = parsed_args["key"].as<std::string>();
    if (key_filename != "-") {
      key_file = std::ifstream(key_filename, std::ios::binary);
      if (key_file.good()) {
        key_input = &key_file;
      } else {
        key_sstream = std::istringstream(key_filename);
        key_input = &key_sstream;
      }
    }
    if (magic_number == util::PasswordCombinedKey)
      second_key = util::KeyLoad<KeySize>(key_input, algorithm_name);
    else if (magic_number == util::NoPasswordKey)
      key = util::KeyLoad<KeySize>(key_input, algorithm_name);
  }
  std::string output_filename = parsed_args["output"].as<std::string>();
  if (output_filename != "-") {
    if (std::filesystem::exists(output_filename) &&
        parsed_args.count("overwrite") == 0) {
      std::string prompt_input = "";
      std::cout << "Overwrite? [y/N]:";
      std::cin >> prompt_input;
      if (prompt_input == "Y" || prompt_input == "y") {
        output_file = std::ofstream(output_filename, std::ios::binary);
        output = &output_file;
      } else {
        std::cerr << "Exiting...\n";
        std::exit(EXIT_FAILURE);
      }
    } else {
      output_file = std::ofstream(output_filename, std::ios::binary);
      output = &output_file;
    }
  }

  algorithm::BASE64 base64;
  algorithm::DRBG_SHA256 drbg;
  drbg.Instantiate(KeySize, false);
  algorithm::Pkcs_7<128> pkcs_7;

  std::unique_ptr<algorithm::op_mode::OperationMode<128, KeySize, 1>>
      encrypt_algorithm = algorithm::op_mode::OPModeFactory<KeySize>(
          algorithm_name, util::XorArrays<KeySize / 8>(key, second_key), iv);
  *encrypt_algorithm << algorithm::op_mode::CipherMode::Decrypt;

  while (input->good()) {
    std::array<std::byte, 16> buffer = {};
    input->read(reinterpret_cast<char*>(buffer.data()), 16);
    std::streamsize read_bytes = input->gcount();
    size_t write_size = 0;
    if (read_bytes == 0) break;

    std::vector<std::byte> data(buffer.begin(), buffer.begin() + read_bytes);

    *encrypt_algorithm << data;

    algorithm::op_mode::OperationModeOutputData<128> output_data;
    *encrypt_algorithm >> output_data;

    write_size = output_data.data.size();
    if (input->peek() == EOF) {
      auto un_padded = pkcs_7.RemovePadding(
          {output_data.data.begin(), output_data.data.end()});
      std::memcpy(output_data.data.data(), un_padded.data.data(),
                  un_padded.data.size());
      write_size = un_padded.real_length;
    }

    output->write(reinterpret_cast<char*>(output_data.data.data()), write_size);
  }
  output->flush();

  std::exit(EXIT_SUCCESS);
}

int HashMain(cxxopts::ParseResult parsed_args, std::string help_string) {
  std::istream* input = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ofstream output_file;

  return 0;
}

int KeygenMain(cxxopts::ParseResult parsed_args, std::string help_string) {
  std::istream* input = &std::cin;
  std::istream* password = &std::cin;
  std::ostream* output = &std::cout;

  std::ifstream input_file;
  std::ifstream password_file;
  std::ofstream output_file;

  return 0;
}

int CallMain(ProgramOperationMode mode, cxxopts::ParseResult parsed_args,
             std::string help_string, std::uint32_t key_bits) {
  switch (key_bits) {
    case 256:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<256>(parsed_args, help_string);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<256>(parsed_args, help_string);
        case ProgramOperationMode::kHash:
          return HashMain(parsed_args, help_string);
        case ProgramOperationMode::kKeygen:
          return KeygenMain(parsed_args, help_string);
        default:
          std::cerr << "An unknown error occurred during mode selection."
                    << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    case 192:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<192>(parsed_args, help_string);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<192>(parsed_args, help_string);
        case ProgramOperationMode::kHash:
          return HashMain(parsed_args, help_string);
        case ProgramOperationMode::kKeygen:
          return KeygenMain(parsed_args, help_string);
        default:
          std::cerr << "An unknown error occurred during mode selection."
                    << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    case 128:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<128>(parsed_args, help_string);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<128>(parsed_args, help_string);
        case ProgramOperationMode::kHash:
          return HashMain(parsed_args, help_string);
        case ProgramOperationMode::kKeygen:
          return KeygenMain(parsed_args, help_string);
        default:
          std::cerr << "An unknown error occurred during mode selection."
                    << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    default:
      std::cerr << "Unsupported keysize.\n";
      std::exit(EXIT_FAILURE);
      break;
  }
}

int main(int argc, char* argv[]) {
  ProgramOperationMode mode = ProgramOperationMode::kError;

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
  auto parsed_args = util::ToplevelArgParse(argc, argv, help_string);

  if (parsed_args.count("help")) {
    std::cout << help_string << std::endl;
    std::exit(EXIT_SUCCESS);
  }

  if (parsed_args.count("Mode") != 0) {
    std::string mode_name = parsed_args["Mode"].as<std::string>();
    if (mode_name != "encrypt" && mode_name != "decrypt" &&
        mode_name != "hash" && mode_name != "keygen") {
      std::cerr << help_string << std::endl;
      std::exit(EXIT_FAILURE);
    }
  } else {
    std::cerr << "A mode shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }

  if (parsed_args["Mode"].as<std::string>() == "encrypt") {
    parsed_args = util::EncryptArgParse(argc, argv, help_string);
    mode = ProgramOperationMode::kEncrypt;
  } else if (parsed_args["Mode"].as<std::string>() == "decrypt") {
    parsed_args = util::DecryptArgParse(argc, argv, help_string);
    mode = ProgramOperationMode::kDecrypt;
  } else if (parsed_args["Mode"].as<std::string>() == "hash") {
    parsed_args = util::HashArgParse(argc, argv, help_string);
    mode = ProgramOperationMode::kHash;
  } else if (parsed_args["Mode"].as<std::string>() == "keygen") {
    parsed_args = util::KeygenArgParse(argc, argv, help_string);
    mode = ProgramOperationMode::kKeygen;
  }

  if (!parsed_args.unmatched().empty()) {
    for (auto arg_name : parsed_args.unmatched()) {
      if (arg_name != "encrypt" && arg_name != "decrypt" &&
          arg_name != "hash" && arg_name != "keygen") {
        std::cerr << help_string << std::endl;
        std::exit(EXIT_FAILURE);
      }
    }
  } else if (parsed_args.count("help")) {
    std::cout << help_string << std::endl;
    std::exit(EXIT_SUCCESS);
  }

  if (parsed_args.count("output") == 0) {
    std::cerr << "An output shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();

  auto it = algorithm::kAlgoBits.find(algorithm_name);
  if (it == algorithm::kAlgoBits.end()) {
    std::cerr << "Unknown algorithm\n";
    std::exit(EXIT_FAILURE);
  }

  return CallMain(mode, parsed_args, help_string, it->second);
}

}  // namespace file_encrypt

int main(int argc, char* argv[]) { return file_encrypt::main(argc, argv); }