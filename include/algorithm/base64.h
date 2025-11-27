#ifndef FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BASE64_H_
#define FILE_ENCRYPT_UTIL_INCLUDE_ALGORITHM_BASE64_H_
#include "algorithm.h"

namespace file_encrypt::algorithm {
class BASE64 : public EncodingAlgorithm {
 public:
  std::vector<std::byte> Encoding(
      const std::vector<std::byte>& data) const override final;
  std::vector<std::byte> Decoding(
      const std::vector<std::byte>& data) const override final;
  std::vector<std::byte> Decoding(const std::string& data) const;

  std::vector<std::byte> ReplaceChar(std::vector<std::byte> data) const;
  std::vector<std::byte> ReplaceChar(const std::string& data) const;

 private:
  static constexpr char kBase64Chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";
  static constexpr std::byte kIBase64[] = {
      static_cast<std::byte>(0x00),  // 0
      static_cast<std::byte>(0x00),  // 1
      static_cast<std::byte>(0x00),  // 2
      static_cast<std::byte>(0x00),  // 3
      static_cast<std::byte>(0x00),  // 4
      static_cast<std::byte>(0x00),  // 5
      static_cast<std::byte>(0x00),  // 6
      static_cast<std::byte>(0x00),  // 7
      static_cast<std::byte>(0x00),  // 8
      static_cast<std::byte>(0x00),  // 9
      static_cast<std::byte>(0x00),  // 10
      static_cast<std::byte>(0x00),  // 11
      static_cast<std::byte>(0x00),  // 12
      static_cast<std::byte>(0x00),  // 13
      static_cast<std::byte>(0x00),  // 14
      static_cast<std::byte>(0x00),  // 15
      static_cast<std::byte>(0x00),  // 16
      static_cast<std::byte>(0x00),  // 17
      static_cast<std::byte>(0x00),  // 18
      static_cast<std::byte>(0x00),  // 19
      static_cast<std::byte>(0x00),  // 20
      static_cast<std::byte>(0x00),  // 21
      static_cast<std::byte>(0x00),  // 22
      static_cast<std::byte>(0x00),  // 23
      static_cast<std::byte>(0x00),  // 24
      static_cast<std::byte>(0x00),  // 25
      static_cast<std::byte>(0x00),  // 26
      static_cast<std::byte>(0x00),  // 27
      static_cast<std::byte>(0x00),  // 28
      static_cast<std::byte>(0x00),  // 29
      static_cast<std::byte>(0x00),  // 30
      static_cast<std::byte>(0x00),  // 31
      static_cast<std::byte>(0x00),  // ' '
      static_cast<std::byte>(0x00),  // '!'
      static_cast<std::byte>(0x00),  // '"'
      static_cast<std::byte>(0x00),  // '#'
      static_cast<std::byte>(0x00),  // '$'
      static_cast<std::byte>(0x00),  // '%'
      static_cast<std::byte>(0x00),  // '&'
      static_cast<std::byte>(0x00),  // '''
      static_cast<std::byte>(0x00),  // '('
      static_cast<std::byte>(0x00),  // ')'
      static_cast<std::byte>(0x00),  // '*'
      static_cast<std::byte>(0x3E),  // '+'
      static_cast<std::byte>(0x00),  // ','
      static_cast<std::byte>(0x3E),  // '-'
      static_cast<std::byte>(0x00),  // '.'
      static_cast<std::byte>(0x3F),  // '/'
      static_cast<std::byte>(0x34),  // '0'
      static_cast<std::byte>(0x35),  // '1'
      static_cast<std::byte>(0x36),  // '2'
      static_cast<std::byte>(0x37),  // '3'
      static_cast<std::byte>(0x38),  // '4'
      static_cast<std::byte>(0x39),  // '5'
      static_cast<std::byte>(0x3A),  // '6'
      static_cast<std::byte>(0x3B),  // '7'
      static_cast<std::byte>(0x3C),  // '8'
      static_cast<std::byte>(0x3D),  // '9'
      static_cast<std::byte>(0x00),  // ':'
      static_cast<std::byte>(0x00),  // ';'
      static_cast<std::byte>(0x00),  // '<'
      static_cast<std::byte>(0x00),  // '='
      static_cast<std::byte>(0x00),  // '>'
      static_cast<std::byte>(0x00),  // '?'
      static_cast<std::byte>(0x00),  // '@'
      static_cast<std::byte>(0x00),  // 'A'
      static_cast<std::byte>(0x01),  // 'B'
      static_cast<std::byte>(0x02),  // 'C'
      static_cast<std::byte>(0x03),  // 'D'
      static_cast<std::byte>(0x04),  // 'E'
      static_cast<std::byte>(0x05),  // 'F'
      static_cast<std::byte>(0x06),  // 'G'
      static_cast<std::byte>(0x07),  // 'H'
      static_cast<std::byte>(0x08),  // 'I'
      static_cast<std::byte>(0x09),  // 'J'
      static_cast<std::byte>(0x0A),  // 'K'
      static_cast<std::byte>(0x0B),  // 'L'
      static_cast<std::byte>(0x0C),  // 'M'
      static_cast<std::byte>(0x0D),  // 'N'
      static_cast<std::byte>(0x0E),  // 'O'
      static_cast<std::byte>(0x0F),  // 'P'
      static_cast<std::byte>(0x10),  // 'Q'
      static_cast<std::byte>(0x11),  // 'R'
      static_cast<std::byte>(0x12),  // 'S'
      static_cast<std::byte>(0x13),  // 'T'
      static_cast<std::byte>(0x14),  // 'U'
      static_cast<std::byte>(0x15),  // 'V'
      static_cast<std::byte>(0x16),  // 'W'
      static_cast<std::byte>(0x17),  // 'X'
      static_cast<std::byte>(0x18),  // 'Y'
      static_cast<std::byte>(0x19),  // 'Z'
      static_cast<std::byte>(0x00),  // '['
      static_cast<std::byte>(0x00),  // '\'
      static_cast<std::byte>(0x00),  // ']'
      static_cast<std::byte>(0x00),  // '^'
      static_cast<std::byte>(0x3F),  // '_'
      static_cast<std::byte>(0x00),  // '`'
      static_cast<std::byte>(0x1A),  // 'a'
      static_cast<std::byte>(0x1B),  // 'b'
      static_cast<std::byte>(0x1C),  // 'c'
      static_cast<std::byte>(0x1D),  // 'd'
      static_cast<std::byte>(0x1E),  // 'e'
      static_cast<std::byte>(0x1F),  // 'f'
      static_cast<std::byte>(0x20),  // 'g'
      static_cast<std::byte>(0x21),  // 'h'
      static_cast<std::byte>(0x22),  // 'i'
      static_cast<std::byte>(0x23),  // 'j'
      static_cast<std::byte>(0x24),  // 'k'
      static_cast<std::byte>(0x25),  // 'l'
      static_cast<std::byte>(0x26),  // 'm'
      static_cast<std::byte>(0x27),  // 'n'
      static_cast<std::byte>(0x28),  // 'o'
      static_cast<std::byte>(0x29),  // 'p'
      static_cast<std::byte>(0x2A),  // 'q'
      static_cast<std::byte>(0x2B),  // 'r'
      static_cast<std::byte>(0x2C),  // 's'
      static_cast<std::byte>(0x2D),  // 't'
      static_cast<std::byte>(0x2E),  // 'u'
      static_cast<std::byte>(0x2F),  // 'v'
      static_cast<std::byte>(0x30),  // 'w'
      static_cast<std::byte>(0x31),  // 'x'
      static_cast<std::byte>(0x32),  // 'y'
      static_cast<std::byte>(0x33),  // 'z'
  };
};
}  // namespace file_encrypt::algorithm

#endif