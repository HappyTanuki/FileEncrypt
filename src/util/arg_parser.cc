#include "util/arg_parser.h"

#include "algorithm/algorithm_traits.h"

namespace file_encrypt::util {

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
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)\n\n"
      "If the '-' option is specified multiple times, stdin inputs are parsed "
      "in the order in which the options are listed above.");

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
  options.add_options()("a,algorithm", "Algorithm to use (default:AES-256-CBC)",
                        cxxopts::value<std::string>()->default_value(
                            file_encrypt::algorithm::AlgorithmTraits<
                                file_encrypt::algorithm::AES_CBC<256>>::name));
  options.add_options()("p,password",
                        "[text|-] password text, or '-' for prompt",
                        cxxopts::value<std::string>());
  options.add_options()(
      "k,key",
      "<file|text|->: key file, BASE64-encoded text, or '-' for stdin. If this "
      "option is omitted, the program will automatically generate a password "
      "key file named key.pem and then prompt for password input.",
      cxxopts::value<std::string>());
  options.add_options()(
      "i,input", "<file|text|-> Input source: file, message, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options()("use-password-only",
                        "Enable password-only encryption.");
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)\n\n"
      "If the '-' option is specified multiple times, stdin inputs are parsed "
      "in the order in which the options are listed above.");

  options.allow_unrecognised_options();
  options.custom_help("encrypt [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult DecryptArgParse(int argc, char* argv[],
                                     std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()(
      "a,algorithm", "Algorithm to use (default:AES-256-CBC)",
      cxxopts::value<std::string>()->default_value("AES-256-CBC"));
  options.add_options()(
      "k,key", "<file|text|-> key file, BASE64 encoded text, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()(
      "i,input",
      "<file|text|-> Input source: file, cipher text, or '-' for stdin",
      cxxopts::value<std::string>());
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options()("p,password",
                        "[text|-] password text or '-' for prompt",
                        cxxopts::value<std::string>());
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)\n\n"
      "If the '-' option is specified multiple times, stdin inputs are parsed "
      "in the order in which the options are listed above.");

  options.allow_unrecognised_options();
  options.custom_help("decrypt [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult HashArgParse(int argc, char* argv[],
                                  std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()(
      "a,algorithm", "Algorithm to use (default:SHA-256)",
      cxxopts::value<std::string>()->default_value("SHA-256"));
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
  options.add_options()("m,merkle", "Generate the hash using a Merkle tree.");
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)\n\n"
      "If the '-' option is specified multiple times, stdin inputs are parsed "
      "in the order in which the options are listed above.");

  options.allow_unrecognised_options();
  options.custom_help("hash [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

cxxopts::ParseResult KeygenArgParse(int argc, char* argv[],
                                    std::string& help_string) {
  cxxopts::Options options(argv[0], PROGRAM_DESCRIPTION);
  options.add_options()(
      "a,algorithm", "Algorithm to use (default:HASH-DRBG)",
      cxxopts::value<std::string>()->default_value("HASH-DRBG"));
  options.add_options()("o,output", "<file|-> Output file or '-' for stdout",
                        cxxopts::value<std::string>());
  options.add_options()("p,password",
                        "[file|text|-] password file, text, or '-' for prompt",
                        cxxopts::value<std::string>());
  options.add_options()("use-non-password-key",
                        "When this flag is set, program will generate "
                        "non-password-key file");
  options.add_options("General")("H,help", "Show this help message");
  options.add_options("General")(
      "overwrite",
      "Overwrite output file if exists (prompts when not specified)\n\n"
      "If the '-' option is specified multiple times, stdin inputs are parsed "
      "in the order in which the options are listed above.");

  options.allow_unrecognised_options();
  options.custom_help("keygen [OPTION...]");

  help_string = options.help();

  return options.parse(argc, argv);
}

}  // namespace file_encrypt::util