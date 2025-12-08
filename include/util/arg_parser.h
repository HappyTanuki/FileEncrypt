#ifndef FILE_ENCRYPT_UTIL_INCLUDE_UTIL_ARG_PARSER_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_UTIL_ARG_PARSER_H_

#include "cxxopts.hpp"

#define PROGRAM_DESCRIPTION \
  "A file encryption, decryption, and hash validation utility."

namespace file_encrypt::util {

cxxopts::ParseResult ToplevelArgParse(int argc, char* argv[],
                                      std::string& help_string);

cxxopts::ParseResult EncryptArgParse(int argc, char* argv[],
                                     std::string& help_string);

cxxopts::ParseResult DecryptArgParse(int argc, char* argv[],
                                     std::string& help_string);

cxxopts::ParseResult HashArgParse(int argc, char* argv[],
                                  std::string& help_string);

}  // namespace file_encrypt::util

#endif