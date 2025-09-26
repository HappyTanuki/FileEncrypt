#include "io/stream.h"

#include <fstream>

namespace file_encrypt::io {

EncodingStream::EncodingStream(
    std::unique_ptr<file_encrypt::algorithm::HashAlgorithm>&& encoder) {
  hash_encoder = std::move(encoder);
}
EncodingStream::EncodingStream(
    std::unique_ptr<file_encrypt::algorithm::BlockCipherAlgorithm>&& encoder) {
  cipher_encoder = std::move(encoder);
}
void EncodingStream::ClearEncoder() {
  hash_encoder = nullptr;
  cipher_encoder = nullptr;
}

EncodingStream& EncodingStream::operator<<(const BitlengthModifier& length) {
  bitlength = length;
  return *this;
}

EncodingStream& EncodingStream::operator<<(const std::vector<std::byte>& data) {
  if (!hash_encoder && !cipher_encoder) {
    return *this;
  }

  if (bitlength.len == 0) {
    bitlength.len = data.size();
  }

  if (hash_encoder) {
    file_encrypt::algorithm::HashAlgorithmInputData input_data;
    input_data.bit_length = bitlength.len;
    input_data.message = data;
    result = std::move(hash_encoder->Digest(input_data).digest);
  } else if (cipher_encoder) {
    file_encrypt::algorithm::CipherAlgorithmInputData input_data;
    input_data.data = data;
    result = std::move(cipher_encoder->Encrypt(input_data).data);
  }

  bitlength.len = 0;
  return *this;
}
EncodingStream& EncodingStream::operator<<(
    const std::filesystem::path& file_path) {
  if (!hash_encoder && !cipher_encoder) {
    return *this;
  }

  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    return *this;
  }

  file_encrypt::algorithm::HashAlgorithmInputData input_data;
  input_data.message.resize(4096);

  while (file && bitlength.len == 0) {
    if (hash_encoder) {
      file.read((char*)input_data.message.data(), 4096);
      input_data.bit_length = file.gcount() * 8;
      hash_encoder->Update(input_data);
    }
  }

  while (file && bitlength.len > 0) {
    if (hash_encoder) {
      file.read((char*)input_data.message.data(),
                4096 > bitlength.len * 8 ? bitlength.len * 8 : 4096);
      input_data.bit_length = file.gcount() * 8;
      bitlength.len -= input_data.bit_length;
      hash_encoder->Update(input_data);
    }
  }

  if (hash_encoder) {
    result = std::move(hash_encoder->Digest().digest);
  }

  bitlength.len = 0;
  return *this;
}
EncodingStream& EncodingStream::operator>>(std::vector<std::byte>& data) {
  data = result;
  return *this;
}

}  // namespace file_encrypt::io