#include <fstream>
#include <regex>

#include "algorithm/algorithm.h"
#include "algorithm/base64.h"
#include "key_loader.h"

namespace file_encrypt::util {

template <std::uint32_t KeySize>
void KeyStore(const std::filesystem::path& file_path,
              std::array<std::byte, KeySize / 8> key,
              const std::string& algorithm_name) {
  std::ofstream file(file_path, std::ios::binary);
  KeyStore<KeySize>(&file, key, algorithm_name);
  file.close();
}

template <std::uint32_t KeySize>
std::array<std::byte, KeySize / 8> KeyLoad(
    const std::filesystem::path& file_path, const std::string& algorithm_name) {
  std::ifstream file(file_path, std::ios::binary);
  auto value = KeyLoad<KeySize>(&file, algorithm_name);
  file.close();
  return value;
}

template <std::uint32_t KeySize>
void KeyStore(std::ostream* stream,
              const std::array<std::byte, KeySize / 8>& key,
              const std::string& algorithm_name) {
  if (!stream->good()) return;

  algorithm::BASE64 base64;
  std::vector<std::byte> key_vector(key.begin(), key.end());

  *stream << "--------BEGIN " + algorithm_name + " KEY--------" << std::endl;
  *stream << util::BytesToStr(base64.Encoding(key_vector)) << std::endl;
  *stream << "--------END " + algorithm_name + " KEY--------" << std::endl;
}

template <std::uint32_t KeySize>
std::array<std::byte, KeySize / 8> KeyLoad(std::istream* stream,
                                           const std::string& algorithm_name) {
  // 실패 시 자동으로 0-filled 리턴
  std::array<std::byte, KeySize / 8> key = {};
  if (!stream->good()) return key;

  const std::string begin_tag =
      "--------BEGIN " + algorithm_name + " KEY--------";
  const std::string end_tag = "--------END " + algorithm_name + " KEY--------";

  // BEGIN/END을 탐색하기 위한 스트림 상태
  bool found_begin = false;
  std::string base64_data;
  std::string buffer;
  buffer.reserve(4096);

  const size_t block_size = 4096;
  std::vector<char> chunk(block_size);

  while (stream->good()) {
    stream->read(chunk.data(), block_size);
    std::streamsize read_size = stream->gcount();
    if (read_size <= 0) break;

    buffer.append(chunk.data(), read_size);

    // BEGIN 태그 찾기 (아직 못 찾은 경우)
    if (!found_begin) {
      size_t pos = buffer.find(begin_tag);
      if (pos == std::string::npos) {
        // 버퍼를 과도하게 키우지 않도록 앞부분을 정리
        if (buffer.size() > begin_tag.size())
          buffer.erase(0, buffer.size() - begin_tag.size());
        continue;
      }

      // BEGIN 태그 이후부터 처리
      found_begin = true;
      buffer.erase(0, pos + begin_tag.size());
    }

    // END 태그 찾기 (BEGIN을 찾은 이후)
    size_t end_pos = buffer.find(end_tag);
    if (end_pos != std::string::npos) {
      // END 태그 직전까지 base64 본문
      base64_data += buffer.substr(0, end_pos);
      // 끝났으므로 더 읽을 필요 없음
      break;
    }

    // END 태그가 없으면 현재 블록 전체를 Base64 데이터로 이어붙인다
    base64_data += buffer;
    buffer.clear();
  }

  // Base64 공백/개행 제거
  base64_data.erase(
      std::remove_if(base64_data.begin(), base64_data.end(),
                     [](unsigned char c) { return std::isspace(c); }),
      base64_data.end());

  // Base64 디코드
  algorithm::BASE64 base64;
  std::vector<std::byte> decoded = base64.Decoding(base64_data);

  std::memcpy(key.data(), decoded.data(), KeySize / 8);
  return key;
}

};  // namespace file_encrypt::util