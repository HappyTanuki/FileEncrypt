#include <fstream>
#include <iostream>

#include "nolibc/getopt.h"

int main(int argc, char* argv[]) {
  int opt;

  std::ifstream input;
  std::ofstream output;
  std::ifstream password;

  input.basic_ios<char>::rdbuf(std::cin.rdbuf());
  output.basic_ios<char>::rdbuf(std::cout.rdbuf());

  while ((opt = nolibc::getopt(argc, argv, "aiop:")) != -1) {
    switch (opt) {
      case 'i':
        if (nolibc::optarg != "-") {
          input = std::ifstream(nolibc::optarg, std::ios::binary);
        }
        break;
      case 'o':
        if (nolibc::optarg != "-") {
          output = std::ofstream(nolibc::optarg, std::ios::binary);
        }
        break;
      default: /* '?' */
        std::cerr << "Usage: " << argv[0]
                  << " -a algorithm"
                     " -i input_file_or_phrase"
                     " -o output_file_or_stream"
                     " [-p password_file_or_phrase]"
                  << "\n";
        std::exit(EXIT_FAILURE);
    }
  }

  if (nolibc::optind >= argc) {
    std::fprintf(stderr, "Expected argument after options\n");
    std::exit(EXIT_FAILURE);
  }

  std::printf("name argument = %s\n", argv[nolibc::optind]);

  /* Other code omitted */

  std::exit(EXIT_SUCCESS);
}