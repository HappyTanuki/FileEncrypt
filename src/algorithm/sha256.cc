#include "algorithm/sha256.h"

#include "precomp.h"
#include <cassert>

namespace file_encrypt::algorithm {

SHA256::SHA256() { Reset(); }

constexpr void SHA256::Reset() {
  std::copy(std::begin(H0), std::end(H0), H.begin());
  data_length = 0;
}

constexpr std::uint32_t SHA256::ROTR(std::uint32_t x, std::uint32_t n) const {
  return (x >> n) | (x << (32 - n));
}
constexpr std::uint32_t SHA256::Ch(std::uint32_t x, std::uint32_t y,
                                   std::uint32_t z) const {
  return (x & y) ^ (~x & z);
}
constexpr std::uint32_t SHA256::Maj(std::uint32_t x, std::uint32_t y,
                                    std::uint32_t z) const {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t SHA256::Sigma0(std::uint32_t x) const {
  return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}
constexpr std::uint32_t SHA256::Sigma1(std::uint32_t x) const {
  return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}
constexpr std::uint32_t SHA256::sigma0(std::uint32_t x) const {
  return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}
constexpr std::uint32_t SHA256::sigma1(std::uint32_t x) const {
  return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

constexpr std::vector<std::array<std::uint32_t, 16>> SHA256::Padding(
    const HashAlgorithmInputData& data) const {
  std::vector<std::array<std::uint32_t, 16>> padded = {};
  padded.resize((data.bit_length + 1 + 64 + 511) / 512);

  for (int i = 0; i < data.message.size(); i++) {
    padded[i / 64][(i / 4) % 16] |= std::to_integer<uint32_t>(data.message[i])
                                    << 8 * (3 - (i % 4));
  }

  padded[data.bit_length / 512][(data.bit_length / 32) % 16] |=
      (1u << (31 - (data.bit_length % 32)));

  padded.back()[14] = static_cast<uint32_t>(data.bit_length >> 32);
  padded.back()[15] = static_cast<uint32_t>(data.bit_length & 0xFFFFFFFF);

  return padded;
}

constexpr std::array<std::uint32_t, 16> SHA256::MakeMessage(
    const std::array<std::byte, 64>& data, std::uint64_t data_bit_length) {
  std::array<std::uint32_t, 16> M = {};

  for (int i = 0; i < 64 && i < (data_bit_length + 7) / 8; i++) {
    M[i / 4] |= std::to_integer<uint32_t>(data[i])
                                    << 8 * (3 - (i % 4));
  }

  return M;
}

constexpr std::array<std::uint32_t, 8> SHA256::ProcessMessageBlock(
    const std::array<std::uint32_t, 16>& M,
    const std::array<std::uint32_t, 8>& H) const {
  std::array<std::uint32_t, 64> W = {};
  for (int t = 0; t < 16; t++) {
    W[t] = M[t];
  }
  for (int t = 16; t < 64; t++) {
    W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
  }
  std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                g = H[6], h = H[7];
  std::uint32_t T1 = 0, T2 = 0;
  for (int t = 0; t < 64; t++) {
    T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
    T2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  return {H[0] + a, H[1] + b, H[2] + c, H[3] + d,
          H[4] + e, H[5] + f, H[6] + g, H[7] + h};
}

HashAlgorithmReturnData SHA256::Digest(
    const HashAlgorithmInputData& data) const {
  std::vector<std::array<std::uint32_t, 16>> M = Padding(data);

  std::array<std::uint32_t, 8> H = {H0[0], H0[1], H0[2], H0[3],
                                    H0[4], H0[5], H0[6], H0[7]};

  for (int i = 0; i < M.size(); i++) {
    H = ProcessMessageBlock(M[i], H);
  }
  HashAlgorithmReturnData ret;
  ret.digest.resize(32);
  for (int i = 0; i < 8; i++) {
    ret.digest[i * 4] = static_cast<std::byte>((H[i] >> 24) & 0xFF);
    ret.digest[i * 4 + 1] = static_cast<std::byte>((H[i] >> 16) & 0xFF);
    ret.digest[i * 4 + 2] = static_cast<std::byte>((H[i] >> 8) & 0xFF);
    ret.digest[i * 4 + 3] = static_cast<std::byte>(H[i] & 0xFF);
  }
  return ret;
}

//void SHA256::Update(const HashAlgorithmInputData& data) { //아마 정확한 구현일텐데 성능 최적화가 그닥일거라 주석,,
//  std::vector<std::byte>::const_iterator data_iterator = data.message.begin();
//
//  data_length += data.bit_length;
//  while (data_iterator != data.message.end()) {
//    while (data_buffer_bit_length < 512 &&
//           data_iterator != data.message.end()) {
//      data_buffer[(data_buffer_bit_length + 7) / 8] = *data_iterator++;
//      data_buffer_bit_length += 8;
//    }
//    if (data_buffer_bit_length == 512) {
//      H = ProcessMessageBlock(MakeMessage(data_buffer, 512), H);
//      data_buffer_bit_length = 0;
//    }
//  }
//}

void SHA256::Update(const HashAlgorithmInputData& data) {
  const uint8_t* input = reinterpret_cast<const uint8_t*>(data.message.data());
  size_t input_bytes = (data.bit_length + 7) / 8;
  size_t buffer_bytes = data_buffer_bit_length / 8;

  data_length += data.bit_length;

  if (buffer_bytes > 0) {
    size_t fill = 64 - buffer_bytes;
    if (input_bytes >= fill) {
      std::memcpy(data_buffer.data() + buffer_bytes, input, fill);
      H = ProcessMessageBlock(MakeMessage(data_buffer, 512), H);
      input += fill;
      input_bytes -= fill;
      data_buffer_bit_length = 0;
      buffer_bytes = 0;
    } else {
      std::memcpy(data_buffer.data() + buffer_bytes, input, input_bytes);
      data_buffer_bit_length += data.bit_length;
      return;
    }
  }

  while (input_bytes >= 64) {
    std::memcpy(data_buffer.data(), input, 64);
    H = ProcessMessageBlock(MakeMessage(data_buffer, 512), H);
    input += 64;
    input_bytes -= 64;
    data_buffer_bit_length = 0;
  }

  if (input_bytes > 0) {
    std::memcpy(data_buffer.data(), input, input_bytes);
    data_buffer_bit_length = data.bit_length % 512;
  }
}

HashAlgorithmReturnData SHA256::Digest() {
  std::array<std::uint32_t, 16> M = {};

  M = MakeMessage(data_buffer, data_buffer_bit_length);
  M[(data_buffer_bit_length / 32) % 16] |=
      (1u << (31 - (data_buffer_bit_length % 32)));

  if (data_buffer_bit_length + 1 + 64 > 512) {
    H = ProcessMessageBlock(M, H);
    M = {};
    M[14] = static_cast<uint32_t>(data_length >> 32);
    M[15] = static_cast<uint32_t>(data_length & 0xFFFFFFFF);
    H = ProcessMessageBlock(M, H);
  } else {
    M[14] = static_cast<uint32_t>(data_length >> 32);
    M[15] = static_cast<uint32_t>(data_length & 0xFFFFFFFF);
    H = ProcessMessageBlock(M, H);
  }
  data_buffer_bit_length = 0;

  HashAlgorithmReturnData ret;
  ret.digest.resize(32);
  for (int i = 0; i < 8; i++) {
    ret.digest[i * 4] = static_cast<std::byte>((H[i] >> 24) & 0xFF);
    ret.digest[i * 4 + 1] = static_cast<std::byte>((H[i] >> 16) & 0xFF);
    ret.digest[i * 4 + 2] = static_cast<std::byte>((H[i] >> 8) & 0xFF);
    ret.digest[i * 4 + 3] = static_cast<std::byte>(H[i] & 0xFF);
  }
  return ret;
}

};  // namespace file_encrypt::algorithm