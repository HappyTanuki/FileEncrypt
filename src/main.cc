#include <fstream>
#include <iostream>
#include <sstream>

#define CXXOPTS_NO_EXCEPTIONS
#define PROGRAM_DESCRIPTION \
  "A file encryption, decryption, and hash validation utility."

#define READ_CHUNK_SIZE 4096

#include "algorithm/algorithm_factory.h"
#include "algorithm/base64.h"
#include "algorithm/block_cipher/mode/aliases.h"
#include "algorithm/csprng/drbg_sha.h"
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
int EncryptMain(cxxopts::ParseResult parsed_args, std::string help_string,
                bool overwrite, bool verbose) {
  std::shared_ptr<std::istream> input;
  std::shared_ptr<std::istream> key_input;
  std::shared_ptr<std::ostream> output;

  algorithm::DRBG_SHA<256> drbg;
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

  std::shared_ptr<file_encrypt::algorithm::HMAC<256>> hmac =
      std::make_shared<file_encrypt::algorithm::HMAC<256>>(
          std::make_unique<file_encrypt::algorithm::SHA<256>>());

  auto salt_return = drbg.Generate(KeySize, KeySize, false, {});
  if (salt_return.status != algorithm::ReturnStatus::kSUCCESS) {
    if (verbose) std::cerr << "CSPRNG error.\n";
    std::exit(EXIT_FAILURE);
  }
  salt = std::move(salt_return.pseudorandom_bits);

  auto iv_return = drbg.Generate(128, KeySize, false, {});
  if (iv_return.status != algorithm::ReturnStatus::kSUCCESS) {
    if (verbose) std::cerr << "CSPRNG error.\n";
    std::exit(EXIT_FAILURE);
  }
  std::memcpy(iv.data(), iv_return.pseudorandom_bits.data(), 16);

  if (!use_password && use_key && parsed_args.count("key") > 0) {
    // 키 입력이 있고 엔트로피 전용모드일 때
    use_key = true;
    std::string key_filename = parsed_args["key"].as<std::string>();
    key_input = util::OpenIStream(key_filename);
    key = util::KeyLoad<KeySize>(key_input, algorithm_name);
  } else if (use_password && !use_key) {
    // 비밀번호 전용모드일 때
    key = algorithm::PBKDF2<256, KeySize>(password, salt, hmac, 600000);
  } else if (use_password && use_key) {
    // 비밀번호 엔트로피 복합모드일 때
    key = algorithm::PBKDF2<256, KeySize>(password, salt, hmac, 600000);
    auto key_return = drbg.Generate(KeySize, KeySize, false, {});
    if (key_return.status != algorithm::ReturnStatus::kSUCCESS) {
      if (verbose) std::cerr << "CSPRNG error.\n";
      std::exit(EXIT_FAILURE);
    }
    std::memcpy(second_key.data(), key_return.pseudorandom_bits.data(),
                KeySize / 8);
  } else {
    // 키 입력이 없고 엔트로피 전용모드일 때
    auto key_return = drbg.Generate(KeySize, KeySize, false, {});
    if (key_return.status != algorithm::ReturnStatus::kSUCCESS) {
      if (verbose) std::cerr << "CSPRNG error.\n";
      std::exit(EXIT_FAILURE);
    }
    std::memcpy(key.data(), key_return.pseudorandom_bits.data(), KeySize / 8);
  }

  if (parsed_args.count("input") == 0) {
    if (verbose)
      std::cerr << "An input shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string input_filename = parsed_args["input"].as<std::string>();
  input = util::OpenIStream(input_filename);

  if (parsed_args.count("output") == 0) {
    if (verbose)
      std::cerr << "An output shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string output_filename = parsed_args["output"].as<std::string>();
  output = util::OpenOStream(output_filename, overwrite, !overwrite);

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

  std::filesystem::path keyname = "key.pem";
  if (use_key && !use_password) {
    // 엔트로피 키 전용모드
    util::KeyStore<KeySize>(keyname, key, algorithm_name);
  } else if (use_key && use_password) {
    // 엔트로피 키 + 비밀번호 모드
    util::KeyStore<KeySize>(keyname, second_key, algorithm_name);
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
int DecryptMain(cxxopts::ParseResult parsed_args, std::string help_string,
                bool overwrite, bool verbose) {
  std::shared_ptr<std::istream> input;
  std::shared_ptr<std::istream> key_input;
  std::shared_ptr<std::ostream> output;

  std::array<std::byte, 4> magic_number;
  std::array<std::byte, KeySize / 8> key;
  std::array<std::byte, KeySize / 8> second_key = {};
  std::array<std::byte, 16> iv;
  std::vector<std::byte> salt(KeySize / 8);

  std::shared_ptr<file_encrypt::algorithm::HMAC<256>> hmac =
      std::make_shared<file_encrypt::algorithm::HMAC<256>>(
          std::make_unique<file_encrypt::algorithm::SHA<256>>());

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();

  if (parsed_args.count("input") == 0) {
    if (verbose)
      std::cerr << "An input shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string input_filename = parsed_args["input"].as<std::string>();
  input = util::OpenIStream(input_filename);

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
    key = algorithm::PBKDF2<256, KeySize>(password, salt, hmac, 600000);
  } else if (magic_number == util::NoPasswordKey) {
    // Nothing to do
  } else {
    // Invalid
    if (verbose) std::cerr << "Unknown file format." << std::endl;
    std::exit(EXIT_FAILURE);
  }

  if ((magic_number == util::PasswordCombinedKey ||
       magic_number == util::NoPasswordKey) &&
      parsed_args.count("key") == 0) {
    if (verbose) std::cerr << "A key shall be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  if (parsed_args.count("key") > 0) {
    std::string key_filename = parsed_args["key"].as<std::string>();
    key_input = util::OpenIStream(key_filename);
    if (magic_number == util::PasswordCombinedKey)
      second_key = util::KeyLoad<KeySize>(key_input, algorithm_name);
    else if (magic_number == util::NoPasswordKey)
      key = util::KeyLoad<KeySize>(key_input, algorithm_name);
  }

  if (parsed_args.count("output") == 0) {
    if (verbose)
      std::cerr << "An output shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }
  std::string output_filename = parsed_args["output"].as<std::string>();
  output = util::OpenOStream(output_filename, overwrite, !overwrite);

  algorithm::BASE64 base64;
  algorithm::DRBG_SHA<256> drbg;
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

template <std::uint32_t DigestSize>
int HashMain(cxxopts::ParseResult parsed_args, std::string help_string,
             bool overwrite, bool verbose) {
  std::shared_ptr<std::istream> input;
  std::shared_ptr<std::ostream> output;

  std::shared_ptr<std::istream> file_a;
  std::shared_ptr<std::istream> file_b;

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();
  std::unique_ptr<algorithm::HashAlgorithm<DigestSize>> hash =
      algorithm::HashFactory<DigestSize>(algorithm_name);

  if (parsed_args.count("diff") > 0) {
    std::vector<std::string> diff_files =
        parsed_args["diff"].as<std::vector<std::string>>();
    if (diff_files.size() != 2) {
      if (verbose)
        std::cerr << "Diff mode expects exactly two files. Received"
                  << diff_files.size() << "." << std::endl;
      std::exit(EXIT_FAILURE);
    }

    file_a = util::OpenIStream(diff_files[0]);
    file_b = util::OpenIStream(diff_files[1]);

    std::array<std::byte, DigestSize / 8> a_digest;
    std::array<std::byte, DigestSize / 8> b_digest;
    while (file_a->good()) {
      algorithm::HashAlgorithmInputData hash_input;
      hash_input.message.resize(READ_CHUNK_SIZE);
      file_a->read(reinterpret_cast<char*>(hash_input.message.data()),
                   READ_CHUNK_SIZE);
      std::streamsize read_bytes = file_a->gcount();
      if (read_bytes == 0) break;
      hash_input.bit_length = read_bytes * 8;

      hash->Update(hash_input);

      if (file_a->peek() == EOF) a_digest = hash->Digest();
    }
    hash->Reset();
    while (file_b->good()) {
      algorithm::HashAlgorithmInputData hash_input;
      hash_input.message.resize(READ_CHUNK_SIZE);
      file_b->read(reinterpret_cast<char*>(hash_input.message.data()),
                   READ_CHUNK_SIZE);
      std::streamsize read_bytes = file_b->gcount();
      if (read_bytes == 0) break;
      hash_input.bit_length = read_bytes * 8;

      hash->Update(hash_input);

      if (file_b->peek() == EOF) b_digest = hash->Digest();
    }
    hash->Reset();

    if (a_digest != b_digest) {
      if (verbose) std::cout << "Files do not match." << std::endl;
      std::exit(EXIT_FAILURE);
    } else {
      if (verbose) std::cout << "Files match." << std::endl;
      std::exit(EXIT_SUCCESS);
    }
  }

  return 0;
}

template <std::uint32_t KeySize>
int KeygenMain(cxxopts::ParseResult parsed_args, std::string help_string,
               bool overwrite, bool verbose) {
  return 0;
}

int CallModeMain(ProgramOperationMode mode, cxxopts::ParseResult parsed_args,
                 std::string help_string, std::uint32_t key_bits,
                 bool overwrite, bool verbose) {
  switch (key_bits) {
    case 256:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<256>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<256>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kHash:
          return HashMain<256>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kKeygen:
          return KeygenMain<256>(parsed_args, help_string, overwrite, verbose);
        default:
          if (verbose)
            std::cerr << "An unknown error occurred during mode selection."
                      << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    case 192:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<192>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<192>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kHash:
          return HashMain<256>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kKeygen:
          return KeygenMain<256>(parsed_args, help_string, overwrite, verbose);
        default:
          if (verbose)
            std::cerr << "An unknown error occurred during mode selection."
                      << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    case 128:
      switch (mode) {
        case ProgramOperationMode::kEncrypt:
          return EncryptMain<128>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kDecrypt:
          return DecryptMain<128>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kHash:
          return HashMain<256>(parsed_args, help_string, overwrite, verbose);
        case ProgramOperationMode::kKeygen:
          return KeygenMain<256>(parsed_args, help_string, overwrite, verbose);
        default:
          if (verbose)
            std::cerr << "An unknown error occurred during mode selection."
                      << std::endl;
          std::exit(EXIT_FAILURE);
      }
      break;
    default:
      if (verbose) std::cerr << "Unsupported keysize.\n";
      std::exit(EXIT_FAILURE);
      break;
  }
}

int main(int argc, char* argv[]) {
  ProgramOperationMode mode = ProgramOperationMode::kError;
  bool overwrite = false;
  bool verbose = false;

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
    if (verbose) std::cerr << "A mode shall always be specified." << std::endl;
    std::exit(EXIT_FAILURE);
  }

  if (parsed_args.count("overwrite") != 0) {
    overwrite = true;
  }
  if (parsed_args.count("verbose") != 0) {
    verbose = true;
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

  std::string algorithm_name = parsed_args["algorithm"].as<std::string>();

  auto it = algorithm::kAlgoBits.find(algorithm_name);
  if (it == algorithm::kAlgoBits.end()) {
    if (verbose) std::cerr << "Unknown algorithm\n";
    std::exit(EXIT_FAILURE);
  }

  return CallModeMain(mode, parsed_args, help_string, it->second, overwrite,
                      verbose);
}

}  // namespace file_encrypt

int main(int argc, char* argv[]) { return file_encrypt::main(argc, argv); }