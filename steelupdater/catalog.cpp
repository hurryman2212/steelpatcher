#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <openssl/evp.h>

#include "catalog.h"
#include "container.h"

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::array<std::uint8_t, 8> kGoPclnMagic{0xF1, 0xFF, 0xFF, 0xFF,
                                                   0x00, 0x00, 0x01, 0x08};
constexpr std::uint32_t kMaximumCommandIntervalMs = 60'000;
constexpr std::uint32_t kMaximumCommandTimeoutMs = 300'000;
constexpr std::uint32_t kMaximumSleepMs = 300'000;
constexpr auto kDefaultVersionQueryTimeout = std::chrono::seconds(2);

Bytes ReadFile(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    throw std::runtime_error("could not open file: " + path.string());
  }
  const std::streamsize size = input.tellg();
  if (size < 0) {
    throw std::runtime_error("could not determine file size: " + path.string());
  }
  input.seekg(0);
  Bytes data(static_cast<std::size_t>(size));
  if (!data.empty() &&
      !input.read(reinterpret_cast<char *>(data.data()), size)) {
    throw std::runtime_error("could not read complete file: " + path.string());
  }
  return data;
}

std::uint16_t ReadLe16(const Bytes &data, std::size_t offset) {
  if (offset > data.size() || 2 > data.size() - offset) {
    throw std::runtime_error("truncated 16-bit value");
  }
  return static_cast<std::uint16_t>(data[offset]) |
         static_cast<std::uint16_t>(data[offset + 1] << 8);
}

std::uint32_t ReadLe32(const Bytes &data, std::size_t offset) {
  if (offset > data.size() || 4 > data.size() - offset) {
    throw std::runtime_error("truncated 32-bit value");
  }
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t ReadLe64(const Bytes &data, std::size_t offset) {
  if (offset > data.size() || 8 > data.size() - offset) {
    throw std::runtime_error("truncated 64-bit value");
  }
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[offset + index]) << (index * 8);
  }
  return value;
}

std::int32_t ReadSignedLe32(const Bytes &data, std::size_t offset) {
  return static_cast<std::int32_t>(ReadLe32(data, offset));
}

std::uint64_t RelativeTarget(std::uint64_t instruction,
                             std::uint64_t instruction_size,
                             std::int32_t displacement) {
  if (instruction_size >
      std::numeric_limits<std::uint64_t>::max() - instruction) {
    throw std::runtime_error("PE relative address overflows");
  }
  const std::uint64_t next = instruction + instruction_size;
  if (displacement < 0) {
    const std::uint64_t magnitude =
        static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
    if (magnitude > next) {
      throw std::runtime_error("PE relative address underflows");
    }
    return next - magnitude;
  }
  const std::uint64_t positive = static_cast<std::uint64_t>(displacement);
  if (positive > std::numeric_limits<std::uint64_t>::max() - next) {
    throw std::runtime_error("PE relative address overflows");
  }
  return next + positive;
}

struct PeSection {
  std::uint64_t address = 0;
  std::size_t raw_offset = 0;
  std::size_t raw_size = 0;
};

class PeImage {
public:
  explicit PeImage(Bytes data) : data_(std::move(data)) {
    if (data_.size() < 0x40 || data_[0] != 'M' || data_[1] != 'Z') {
      throw std::runtime_error("SteelSeriesEngine.exe is not a PE image");
    }
    const std::size_t pe = ReadLe32(data_, 0x3C);
    if (pe + 24 > data_.size() || data_[pe] != 'P' || data_[pe + 1] != 'E' ||
        data_[pe + 2] != 0 || data_[pe + 3] != 0) {
      throw std::runtime_error("SteelSeriesEngine.exe has no PE signature");
    }
    const std::size_t coff = pe + 4;
    const std::size_t section_count = ReadLe16(data_, coff + 2);
    const std::size_t optional_size = ReadLe16(data_, coff + 16);
    const std::size_t optional = coff + 20;
    if (ReadLe16(data_, optional) != 0x20B) {
      throw std::runtime_error("SteelSeriesEngine.exe is not PE32+");
    }
    const std::uint64_t image_base = ReadLe64(data_, optional + 24);
    const std::size_t table = optional + optional_size;
    for (std::size_t index = 0; index < section_count; ++index) {
      const std::size_t header = table + index * 40;
      if (header + 40 > data_.size()) {
        throw std::runtime_error("truncated PE section table");
      }
      sections_.push_back({image_base + ReadLe32(data_, header + 12),
                           ReadLe32(data_, header + 20),
                           ReadLe32(data_, header + 16)});
    }
  }

  const Bytes &Data() const { return data_; }

  Bytes Read(std::uint64_t address, std::size_t size) const {
    for (const PeSection &section : sections_) {
      if (address < section.address) {
        continue;
      }
      const std::uint64_t relative = address - section.address;
      if (relative <= section.raw_size && size <= section.raw_size - relative) {
        const std::size_t offset =
            section.raw_offset + static_cast<std::size_t>(relative);
        if (offset <= data_.size() && size <= data_.size() - offset) {
          return Bytes(data_.begin() + static_cast<std::ptrdiff_t>(offset),
                       data_.begin() +
                           static_cast<std::ptrdiff_t>(offset + size));
        }
      }
    }
    throw std::runtime_error("PE virtual address is not backed by file data");
  }

private:
  Bytes data_;
  std::vector<PeSection> sections_;
};

std::string CString(const Bytes &data, std::size_t offset) {
  if (offset >= data.size()) {
    throw std::runtime_error("truncated Go function name");
  }
  const auto end = std::find(data.begin() + static_cast<std::ptrdiff_t>(offset),
                             data.end(), 0);
  if (end == data.end()) {
    throw std::runtime_error("unterminated Go function name");
  }
  return std::string(data.begin() + static_cast<std::ptrdiff_t>(offset), end);
}

std::map<std::string, std::pair<std::uint64_t, std::size_t>>
GoFunctions(const Bytes &data) {
  auto candidate = data.begin();
  while ((candidate = std::search(candidate, data.end(), kGoPclnMagic.begin(),
                                  kGoPclnMagic.end())) != data.end()) {
    const std::size_t pcln =
        static_cast<std::size_t>(std::distance(data.begin(), candidate));
    ++candidate;
    try {
      const std::uint64_t count = ReadLe64(data, pcln + 8);
      const std::uint64_t text_start = ReadLe64(data, pcln + 24);
      const std::size_t names =
          pcln + static_cast<std::size_t>(ReadLe64(data, pcln + 32));
      const std::size_t table =
          pcln + static_cast<std::size_t>(ReadLe64(data, pcln + 64));
      if (count == 0 || count >= 1'000'000 ||
          table + static_cast<std::size_t>(count) * 8 + 4 > data.size()) {
        continue;
      }
      std::map<std::string, std::pair<std::uint64_t, std::size_t>> functions;
      for (std::size_t index = 0; index < count; ++index) {
        const std::uint32_t entry = ReadLe32(data, table + index * 8);
        const std::size_t record =
            table + ReadLe32(data, table + index * 8 + 4);
        if (ReadLe32(data, record) != entry) {
          throw std::runtime_error("inconsistent Go function table");
        }
        const std::string name =
            CString(data, names + ReadLe32(data, record + 4));
        const std::uint32_t next = ReadLe32(data, table + (index + 1) * 8);
        if (next < entry) {
          throw std::runtime_error("unordered Go function table");
        }
        functions.emplace(name,
                          std::pair{text_start + entry,
                                    static_cast<std::size_t>(next - entry)});
      }
      return functions;
    } catch (const std::runtime_error &) {
    }
  }
  throw std::runtime_error(
      "SteelSeriesEngine.exe has no supported Go function table");
}

std::pair<std::uint64_t, std::size_t> UniqueFunction(
    const std::map<std::string, std::pair<std::uint64_t, std::size_t>>
        &functions,
    std::string_view suffix) {
  std::optional<std::pair<std::uint64_t, std::size_t>> result;
  for (const auto &[name, location] : functions) {
    if (name.size() >= suffix.size() &&
        name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
      if (result) {
        throw std::runtime_error("ambiguous Go function ending in " +
                                 std::string(suffix));
      }
      result = location;
    }
  }
  if (!result) {
    throw std::runtime_error("missing Go function ending in " +
                             std::string(suffix));
  }
  return *result;
}

Bytes ExtractDescriptorPassword(const Bytes &engine) {
  const PeImage image(engine);
  const auto functions = GoFunctions(engine);
  const auto callback =
      UniqueFunction(functions, "fileencryption.DecryptDeviceFile.func1");
  const auto concat = UniqueFunction(functions, "runtime.concatbyte2");
  const Bytes code = image.Read(callback.first, callback.second);
  std::vector<std::size_t> matches;
  for (std::size_t offset = 0; offset + 27 <= code.size(); ++offset) {
    if (code[offset] == 0x48 && code[offset + 1] == 0x8D &&
        code[offset + 2] == 0x05 && code[offset + 7] == 0xBB &&
        code[offset + 12] == 0x48 && code[offset + 13] == 0x8D &&
        code[offset + 14] == 0x0D && code[offset + 19] == 0x48 &&
        code[offset + 20] == 0x89 && code[offset + 21] == 0xDF &&
        code[offset + 22] == 0xE8) {
      matches.push_back(offset);
    }
  }
  if (matches.size() != 1) {
    throw std::runtime_error(
        "descriptor password callback has an unsupported layout");
  }
  const std::size_t offset = matches.front();
  const std::uint64_t instruction = callback.first + offset;
  const std::size_t size = ReadLe32(code, offset + 8);
  const std::uint64_t first =
      RelativeTarget(instruction, 7, ReadSignedLe32(code, offset + 3));
  const std::uint64_t second =
      RelativeTarget(instruction, 19, ReadSignedLe32(code, offset + 15));
  const std::uint64_t call =
      RelativeTarget(instruction, 27, ReadSignedLe32(code, offset + 23));
  if (size != 64 || call != concat.first) {
    throw std::runtime_error(
        "descriptor password callback failed structural validation");
  }
  Bytes password = image.Read(first, size);
  const Bytes tail = image.Read(second, size);
  password.insert(password.end(), tail.begin(), tail.end());
  if (!std::all_of(password.begin(), password.end(), [](std::uint8_t byte) {
        return byte >= 0x20 && byte < 0x7F;
      })) {
    throw std::runtime_error("descriptor password is not printable ASCII");
  }
  return password;
}

Bytes Base64Decode(std::string_view text) {
  if (text.empty() || text.size() % 4 != 0 ||
      text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("invalid descriptor base64 length");
  }
  Bytes output(text.size() / 4 * 3);
  const int decoded = EVP_DecodeBlock(
      output.data(), reinterpret_cast<const unsigned char *>(text.data()),
      static_cast<int>(text.size()));
  if (decoded < 0) {
    throw std::runtime_error("invalid descriptor base64");
  }
  std::size_t size = static_cast<std::size_t>(decoded);
  if (!text.empty() && text.back() == '=') {
    --size;
  }
  if (text.size() >= 2 && text[text.size() - 2] == '=') {
    --size;
  }
  output.resize(size);
  return output;
}

std::uint32_t Crc24(const Bytes &data) {
  std::uint32_t crc = 0xB704CE;
  for (const std::uint8_t byte : data) {
    crc ^= static_cast<std::uint32_t>(byte) << 16;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc <<= 1;
      if ((crc & 0x1000000) != 0) {
        crc ^= 0x1864CFB;
      }
    }
  }
  return crc & 0xFFFFFF;
}

Bytes DecodeArmor(const Bytes &data) {
  std::string text(data.begin(), data.end());
  std::istringstream input(text);
  std::vector<std::string> lines;
  for (std::string line; std::getline(input, line);) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    lines.push_back(std::move(line));
  }
  if (lines.size() < 5 || lines.front() != "-----BEGIN DESCRIPTOR-----" ||
      lines.back() != "-----END DESCRIPTOR-----") {
    throw std::runtime_error("invalid descriptor armor markers");
  }
  const auto separator = std::find(lines.begin() + 1, lines.end(), "");
  if (separator == lines.end()) {
    throw std::runtime_error("descriptor armor has no header separator");
  }
  const std::size_t separator_index =
      static_cast<std::size_t>(std::distance(lines.begin(), separator));
  std::string encoded;
  std::string checksum;
  for (std::size_t index = separator_index + 1; index + 1 < lines.size();
       ++index) {
    const std::string &line = lines[index];
    if (!line.empty() && line.front() == '=') {
      if (!checksum.empty()) {
        throw std::runtime_error("descriptor armor has multiple checksums");
      }
      checksum = line.substr(1);
    } else if (!checksum.empty() || line.empty()) {
      throw std::runtime_error("malformed descriptor armor payload");
    } else {
      encoded += line;
    }
  }
  if (checksum.empty()) {
    throw std::runtime_error("descriptor armor has no checksum");
  }
  const Bytes payload = Base64Decode(encoded);
  const Bytes decoded_checksum = Base64Decode(checksum);
  const std::uint32_t crc = Crc24(payload);
  if (decoded_checksum.size() != 3 ||
      decoded_checksum[0] != static_cast<std::uint8_t>(crc >> 16) ||
      decoded_checksum[1] != static_cast<std::uint8_t>(crc >> 8) ||
      decoded_checksum[2] != static_cast<std::uint8_t>(crc)) {
    throw std::runtime_error("descriptor armor checksum is invalid");
  }
  return payload;
}

std::tuple<std::size_t, std::size_t, bool> PacketLength(const Bytes &data,
                                                        std::size_t offset) {
  if (offset >= data.size()) {
    throw std::runtime_error("truncated OpenPGP packet length");
  }
  const std::uint8_t first = data[offset++];
  if (first < 192) {
    return {first, offset, false};
  }
  if (first < 224) {
    if (offset >= data.size()) {
      throw std::runtime_error("truncated OpenPGP packet length");
    }
    return {static_cast<std::size_t>(((first - 192) << 8) + data[offset] + 192),
            offset + 1, false};
  }
  if (first == 255) {
    if (offset + 4 > data.size()) {
      throw std::runtime_error("truncated OpenPGP packet length");
    }
    const std::size_t size =
        (static_cast<std::size_t>(data[offset]) << 24) |
        (static_cast<std::size_t>(data[offset + 1]) << 16) |
        (static_cast<std::size_t>(data[offset + 2]) << 8) | data[offset + 3];
    return {size, offset + 4, false};
  }
  return {std::size_t{1} << (first & 0x1F), offset, true};
}

struct Packet {
  unsigned tag = 0;
  Bytes body;
};

std::vector<Packet> Packets(const Bytes &data) {
  std::vector<Packet> packets;
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::uint8_t header = data[offset++];
    if ((header & 0x80) == 0) {
      throw std::runtime_error("invalid OpenPGP packet header");
    }
    unsigned tag = 0;
    std::size_t size = 0;
    if ((header & 0x40) == 0) {
      tag = (header >> 2) & 0x0F;
      const unsigned length_type = header & 0x03;
      if (length_type == 3) {
        size = data.size() - offset;
      } else {
        const std::size_t length_size = std::size_t{1} << length_type;
        if (offset + length_size > data.size()) {
          throw std::runtime_error("truncated OpenPGP packet length");
        }
        for (std::size_t index = 0; index < length_size; ++index) {
          size = (size << 8) | data[offset++];
        }
      }
      if (offset + size > data.size()) {
        throw std::runtime_error("truncated OpenPGP packet");
      }
      packets.push_back(
          {tag,
           Bytes(data.begin() + static_cast<std::ptrdiff_t>(offset),
                 data.begin() + static_cast<std::ptrdiff_t>(offset + size))});
      offset += size;
      continue;
    }
    tag = header & 0x3F;
    Bytes body;
    bool partial = false;
    do {
      std::tie(size, offset, partial) = PacketLength(data, offset);
      if (offset + size > data.size()) {
        throw std::runtime_error("truncated OpenPGP packet");
      }
      body.insert(body.end(),
                  data.begin() + static_cast<std::ptrdiff_t>(offset),
                  data.begin() + static_cast<std::ptrdiff_t>(offset + size));
      offset += size;
    } while (partial);
    packets.push_back({tag, std::move(body)});
  }
  return packets;
}

Bytes Digest(const EVP_MD *algorithm, const Bytes &data) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1) {
    throw std::runtime_error("could not initialize descriptor digest");
  }
  Bytes digest(static_cast<std::size_t>(EVP_MD_get_size(algorithm)));
  unsigned size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1) {
    throw std::runtime_error("could not finish descriptor digest");
  }
  digest.resize(size);
  return digest;
}

Bytes DeriveKey(const Bytes &password, const Bytes &salt,
                std::uint8_t count_byte, std::size_t size) {
  const std::size_t count = (std::size_t{16} + (count_byte & 15u))
                            << ((count_byte >> 4u) + 6u);
  Bytes block = salt;
  block.insert(block.end(), password.begin(), password.end());
  if (block.empty() || count > std::size_t{64} * 1024 * 1024) {
    throw std::runtime_error("unsupported OpenPGP S2K work factor");
  }
  Bytes material;
  material.reserve(std::max(count, block.size()));
  while (material.size() < std::max(count, block.size())) {
    const std::size_t remaining =
        std::max(count, block.size()) - material.size();
    material.insert(material.end(), block.begin(),
                    block.begin() + static_cast<std::ptrdiff_t>(
                                        std::min(remaining, block.size())));
  }
  Bytes key;
  for (std::size_t prefix = 0; key.size() < size; ++prefix) {
    Bytes input(prefix, 0);
    input.insert(input.end(), material.begin(), material.end());
    const Bytes hash = Digest(EVP_sha256(), input);
    key.insert(key.end(), hash.begin(), hash.end());
  }
  key.resize(size);
  return key;
}

const EVP_CIPHER *CipherFor(unsigned algorithm) {
  switch (algorithm) {
  case 7:
    return EVP_aes_128_cfb128();
  case 8:
    return EVP_aes_192_cfb128();
  case 9:
    return EVP_aes_256_cfb128();
  default:
    throw std::runtime_error("unsupported OpenPGP AES algorithm");
  }
}

Bytes AesCfbDecrypt(const Bytes &data, const Bytes &key, unsigned algorithm) {
  if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error("descriptor cipher payload is too large");
  }
  const EVP_CIPHER *cipher = CipherFor(algorithm);
  std::array<std::uint8_t, 16> iv{};
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
      EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context || EVP_DecryptInit_ex(context.get(), cipher, nullptr, key.data(),
                                     iv.data()) != 1) {
    throw std::runtime_error("could not initialize descriptor cipher");
  }
  Bytes output(data.size() + 16);
  int first = 0;
  int last = 0;
  if (EVP_DecryptUpdate(context.get(), output.data(), &first, data.data(),
                        static_cast<int>(data.size())) != 1 ||
      EVP_DecryptFinal_ex(context.get(), output.data() + first, &last) != 1) {
    throw std::runtime_error("could not decrypt descriptor payload");
  }
  if (first < 0 || last < 0) {
    throw std::runtime_error("descriptor cipher returned an invalid size");
  }
  output.resize(static_cast<std::size_t>(first) +
                static_cast<std::size_t>(last));
  return output;
}

Bytes DecryptDescriptor(const Bytes &armored, const Bytes &password) {
  const std::vector<Packet> packets = Packets(DecodeArmor(armored));
  if (packets.size() != 2 || packets[0].tag != 3 || packets[1].tag != 18) {
    throw std::runtime_error("unsupported descriptor OpenPGP layout");
  }
  const Bytes &symmetric = packets[0].body;
  if (symmetric.size() < 13 || symmetric[0] != 4 || symmetric[2] != 3 ||
      symmetric[3] != 8) {
    throw std::runtime_error("unsupported descriptor symmetric-key packet");
  }
  unsigned algorithm = symmetric[1];
  const EVP_CIPHER *cipher = CipherFor(algorithm);
  const std::size_t key_size =
      static_cast<std::size_t>(EVP_CIPHER_get_key_length(cipher));
  const Bytes salt(symmetric.begin() + 4, symmetric.begin() + 12);
  const Bytes derived = DeriveKey(password, salt, symmetric[12], key_size);
  Bytes key = derived;
  if (symmetric.size() > 13) {
    const Bytes encrypted(symmetric.begin() + 13, symmetric.end());
    const Bytes session = AesCfbDecrypt(encrypted, derived, algorithm);
    if (session.size() < 2) {
      throw std::runtime_error("invalid descriptor session key");
    }
    algorithm = session[0];
    key.assign(session.begin() + 1, session.end());
    if (key.size() != static_cast<std::size_t>(
                          EVP_CIPHER_get_key_length(CipherFor(algorithm)))) {
      throw std::runtime_error("descriptor session key has the wrong size");
    }
  }
  if (packets[1].body.empty() || packets[1].body[0] != 1) {
    throw std::runtime_error("descriptor payload is not integrity protected");
  }
  const Bytes encrypted(packets[1].body.begin() + 1, packets[1].body.end());
  const Bytes plaintext = AesCfbDecrypt(encrypted, key, algorithm);
  if (plaintext.size() < 40 || plaintext[14] != plaintext[16] ||
      plaintext[15] != plaintext[17] ||
      plaintext[plaintext.size() - 22] != 0xD3 ||
      plaintext[plaintext.size() - 21] != 0x14) {
    throw std::runtime_error("descriptor OpenPGP integrity framing is invalid");
  }
  const Bytes authenticated(plaintext.begin(), plaintext.end() - 20);
  const Bytes expected = Digest(EVP_sha1(), authenticated);
  if (!std::equal(expected.begin(), expected.end(), plaintext.end() - 20)) {
    throw std::runtime_error("descriptor OpenPGP integrity check failed");
  }
  const Bytes literal_data(plaintext.begin() + 18, plaintext.end() - 22);
  const std::vector<Packet> literal_packets = Packets(literal_data);
  if (literal_packets.size() != 1 || literal_packets[0].tag != 11 ||
      literal_packets[0].body.size() < 6) {
    throw std::runtime_error("descriptor has no literal OpenPGP packet");
  }
  const Bytes &literal = literal_packets[0].body;
  const std::size_t payload = 2 + literal[1] + 4;
  if (payload > literal.size()) {
    throw std::runtime_error("truncated descriptor literal packet");
  }
  return Bytes(literal.begin() + static_cast<std::ptrdiff_t>(payload),
               literal.end());
}

enum class NodeKind : std::uint8_t { kAtom, kString, kList };

struct Node {
  NodeKind kind = NodeKind::kAtom;
  char delimiter = 0;
  std::string text;
  std::vector<Node> children;
};

using Bindings = std::vector<std::pair<std::string, Node>>;

class Parser {
public:
  explicit Parser(std::string_view source) : source_(source) {}

  std::vector<Node> Parse() {
    std::vector<Node> nodes;
    SkipSpace();
    while (offset_ < source_.size()) {
      nodes.push_back(ParseNode());
      SkipSpace();
    }
    return nodes;
  }

private:
  void SkipSpace() {
    for (;;) {
      while (offset_ < source_.size() &&
             std::isspace(static_cast<unsigned char>(source_[offset_]))) {
        ++offset_;
      }
      if (offset_ < source_.size() && source_[offset_] == ';') {
        while (offset_ < source_.size() && source_[offset_] != '\n') {
          ++offset_;
        }
        continue;
      }
      return;
    }
  }

  Node ParseNode() {
    SkipSpace();
    while (offset_ < source_.size() &&
           (source_[offset_] == '\'' || source_[offset_] == '`' ||
            source_[offset_] == ',')) {
      ++offset_;
      SkipSpace();
    }
    if (offset_ >= source_.size()) {
      throw std::runtime_error("unexpected end of descriptor source");
    }
    const char character = source_[offset_];
    if (character == '(' || character == '[' || character == '{') {
      const char close = character == '(' ? ')' : character == '[' ? ']' : '}';
      Node node{NodeKind::kList, character, {}, {}};
      ++offset_;
      SkipSpace();
      while (offset_ < source_.size() && source_[offset_] != close) {
        node.children.push_back(ParseNode());
        SkipSpace();
      }
      if (offset_ >= source_.size()) {
        throw std::runtime_error("unterminated descriptor list");
      }
      ++offset_;
      return node;
    }
    if (character == '"') {
      ++offset_;
      std::string text;
      while (offset_ < source_.size() && source_[offset_] != '"') {
        if (source_[offset_] == '\\') {
          ++offset_;
          if (offset_ >= source_.size()) {
            throw std::runtime_error("truncated descriptor string escape");
          }
          const char escaped = source_[offset_++];
          text += escaped == 'n' ? '\n' : escaped == 'r' ? '\r' : escaped;
        } else {
          text += source_[offset_++];
        }
      }
      if (offset_ >= source_.size()) {
        throw std::runtime_error("unterminated descriptor string");
      }
      ++offset_;
      return {NodeKind::kString, 0, std::move(text), {}};
    }
    const std::size_t start = offset_;
    while (offset_ < source_.size() &&
           !std::isspace(static_cast<unsigned char>(source_[offset_])) &&
           std::string_view("()[]{}'`,;\"").find(source_[offset_]) ==
               std::string_view::npos) {
      ++offset_;
    }
    if (start == offset_) {
      throw std::runtime_error("unexpected descriptor token");
    }
    return {NodeKind::kAtom,
            0,
            std::string(source_.substr(start, offset_ - start)),
            {}};
  }

  std::string_view source_;
  std::size_t offset_ = 0;
};

std::string_view Head(const Node &node) {
  if (node.kind != NodeKind::kList || node.children.empty() ||
      node.children.front().kind != NodeKind::kAtom) {
    return {};
  }
  return node.children.front().text;
}

bool ContainsAtom(const Node &node, std::string_view atom) {
  if (node.kind == NodeKind::kAtom) {
    return node.text == atom;
  }
  return std::any_of(
      node.children.begin(), node.children.end(),
      [atom](const Node &child) { return ContainsAtom(child, atom); });
}

std::vector<const Node *> FindNodes(const Node &node, std::string_view head) {
  std::vector<const Node *> result;
  std::function<void(const Node &)> visit = [&](const Node &current) {
    if (Head(current) == head) {
      result.push_back(&current);
    }
    for (const Node &child : current.children) {
      visit(child);
    }
  };
  visit(node);
  return result;
}

using Value = std::variant<std::int64_t, std::string, Bytes>;

struct Function {
  std::vector<std::string> parameters;
  std::vector<Node> body;
};

struct Scope {
  std::unordered_map<std::string, Node> constants;
  std::unordered_map<std::string, Function> functions;
};

std::optional<std::int64_t> ParseInteger(std::string_view text) {
  int base = 10;
  bool negative = false;
  if (!text.empty() && text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  }
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
    text.remove_prefix(2);
  }
  if (text.empty()) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
      value > static_cast<std::uint64_t>(
                  std::numeric_limits<std::int64_t>::max())) {
    return std::nullopt;
  }
  return negative ? -static_cast<std::int64_t>(value)
                  : static_cast<std::int64_t>(value);
}

void AddDefinition(const Node &node, Scope &scope) {
  const std::string_view head = Head(node);
  if ((head != "define" && head != "defmacro") || node.children.size() < 3) {
    return;
  }
  const Node &declaration = node.children[1];
  if (declaration.kind == NodeKind::kAtom) {
    scope.constants[declaration.text] = node.children[2];
    return;
  }
  if (declaration.kind != NodeKind::kList || declaration.children.empty() ||
      declaration.children[0].kind != NodeKind::kAtom) {
    return;
  }
  Function function;
  for (std::size_t index = 1; index < declaration.children.size(); ++index) {
    if (declaration.children[index].kind != NodeKind::kAtom) {
      return;
    }
    function.parameters.push_back(declaration.children[index].text);
  }
  function.body.assign(node.children.begin() + 2, node.children.end());
  scope.functions[declaration.children[0].text] = std::move(function);
}

std::vector<const Node *> FindReachableNodes(const Node &node,
                                             std::string_view target_head,
                                             const Scope &scope) {
  std::vector<const Node *> result;
  std::set<std::string> expanded_functions;
  std::function<void(const Node &)> visit = [&](const Node &current) {
    const std::string_view head = Head(current);
    if (head == "define" || head == "defmacro") {
      return;
    }
    if (head == target_head) {
      result.push_back(&current);
    }
    for (const Node &child : current.children) {
      visit(child);
    }
    if (head.empty()) {
      return;
    }
    const auto function = scope.functions.find(std::string(head));
    if (function == scope.functions.end() ||
        !expanded_functions.insert(function->first).second) {
      return;
    }
    for (const Node &body : function->second.body) {
      visit(body);
    }
  };
  visit(node);
  return result;
}

class Evaluator {
public:
  explicit Evaluator(const Scope &scope) : scope_(scope) {
    variables_["HIDIO"] = std::int64_t{0};
    variables_["HIDIONOFAIL"] = std::int64_t{0};
  }

  void Set(std::string name, Value value) {
    variables_[std::move(name)] = std::move(value);
  }

  Value Evaluate(const Node &node) { return Evaluate(node, 0); }

  std::int64_t Integer(const Node &node) {
    return std::get<std::int64_t>(Evaluate(node));
  }

  Bytes ByteArray(const Node &node) { return AsBytes(Evaluate(node)); }

  std::string String(const Node &node) {
    const Value value = Evaluate(node);
    if (const auto *text = std::get_if<std::string>(&value)) {
      return *text;
    }
    if (const auto *number = std::get_if<std::int64_t>(&value)) {
      return std::to_string(*number);
    }
    throw std::runtime_error("descriptor value is not a string");
  }

  bool Predicate(const std::string &name, const Bytes &argument) {
    return AsInteger(Invoke(name, {argument}, 0)) != 0;
  }

private:
  static std::int64_t AsInteger(const Value &value) {
    if (!std::holds_alternative<std::int64_t>(value)) {
      throw std::runtime_error("descriptor value is not an integer");
    }
    return std::get<std::int64_t>(value);
  }

  static Bytes AsBytes(const Value &value) {
    if (const auto *bytes = std::get_if<Bytes>(&value)) {
      return *bytes;
    }
    if (const auto *number = std::get_if<std::int64_t>(&value)) {
      return {static_cast<std::uint8_t>(*number)};
    }
    if (const auto *text = std::get_if<std::string>(&value)) {
      return Bytes(text->begin(), text->end());
    }
    throw std::runtime_error("descriptor value is not byte-compatible");
  }

  static bool Equal(const Value &left, const Value &right) {
    return left == right;
  }

  static std::int64_t Arithmetic(std::string_view operation, std::int64_t left,
                                 std::int64_t right) {
    constexpr std::int64_t minimum = std::numeric_limits<std::int64_t>::min();
    constexpr std::int64_t maximum = std::numeric_limits<std::int64_t>::max();
    if (operation == "+") {
      if ((right > 0 && left > maximum - right) ||
          (right < 0 && left < minimum - right)) {
        throw std::runtime_error("descriptor addition overflows");
      }
      return left + right;
    }
    if (operation == "-") {
      if ((right > 0 && left < minimum + right) ||
          (right < 0 && left > maximum + right)) {
        throw std::runtime_error("descriptor subtraction overflows");
      }
      return left - right;
    }
    if (operation == "*") {
      const bool overflows =
          left > 0
              ? (right > 0 ? left > maximum / right : right < minimum / left)
          : left < 0 ? (right > 0 ? left < minimum / right
                                  : right != 0 && left < maximum / right)
                     : false;
      if (overflows) {
        throw std::runtime_error("descriptor multiplication overflows");
      }
      return left * right;
    }
    if (right == 0) {
      throw std::runtime_error("descriptor division by zero");
    }
    if (left == minimum && right == -1) {
      throw std::runtime_error("descriptor division overflows");
    }
    return left / right;
  }

  Value Invoke(const std::string &name, const std::vector<Value> &arguments,
               unsigned depth) {
    const auto function = scope_.functions.find(name);
    if (function == scope_.functions.end() ||
        function->second.parameters.size() != arguments.size()) {
      throw std::runtime_error("unknown descriptor function: " + name);
    }
    const auto saved = variables_;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      variables_[function->second.parameters[index]] = arguments[index];
    }
    try {
      Value result = std::int64_t{0};
      for (const Node &body : function->second.body) {
        result = Evaluate(body, depth + 1);
      }
      variables_ = saved;
      return result;
    } catch (...) {
      variables_ = saved;
      throw;
    }
  }

  Value Evaluate(const Node &node, unsigned depth) {
    if (depth > 128) {
      throw std::runtime_error("descriptor evaluation recursion is too deep");
    }
    if (node.kind == NodeKind::kString) {
      return node.text;
    }
    if (node.kind == NodeKind::kAtom) {
      if (const auto number = ParseInteger(node.text)) {
        return *number;
      }
      if (node.text == "#t") {
        return std::int64_t{1};
      }
      if (node.text == "#f" || node.text == "nil") {
        return std::int64_t{0};
      }
      if (const auto variable = variables_.find(node.text);
          variable != variables_.end()) {
        return variable->second;
      }
      if (const auto constant = scope_.constants.find(node.text);
          constant != scope_.constants.end()) {
        return Evaluate(constant->second, depth + 1);
      }
      if (const auto function = scope_.functions.find(node.text);
          function != scope_.functions.end() &&
          function->second.parameters.empty()) {
        Value result = std::int64_t{0};
        for (const Node &body : function->second.body) {
          result = Evaluate(body, depth + 1);
        }
        return result;
      }
      throw std::runtime_error("unknown descriptor symbol: " + node.text);
    }
    if (node.delimiter == '[') {
      Bytes result;
      for (const Node &child : node.children) {
        const Bytes bytes = AsBytes(Evaluate(child, depth + 1));
        result.insert(result.end(), bytes.begin(), bytes.end());
      }
      return result;
    }
    if (node.children.empty() || node.children[0].kind != NodeKind::kAtom) {
      throw std::runtime_error("descriptor expression has no callable head");
    }
    const std::string &name = node.children[0].text;
    if (node.children.size() == 1) {
      if (const auto variable = variables_.find(name);
          variable != variables_.end()) {
        return variable->second;
      }
    }
    if (name == "let" || name == "let*") {
      if (node.children.size() < 3 ||
          node.children[1].kind != NodeKind::kList) {
        throw std::runtime_error("invalid descriptor let expression");
      }
      const auto saved = variables_;
      try {
        std::vector<std::pair<std::string, Value>> bindings;
        for (const Node &binding : node.children[1].children) {
          if (binding.kind != NodeKind::kList || binding.children.size() != 2 ||
              binding.children[0].kind != NodeKind::kAtom) {
            throw std::runtime_error("invalid descriptor let binding");
          }
          Value value = Evaluate(binding.children[1], depth + 1);
          if (name == "let*") {
            variables_[binding.children[0].text] = value;
          } else {
            bindings.emplace_back(binding.children[0].text, std::move(value));
          }
        }
        for (auto &[binding, value] : bindings) {
          variables_[binding] = std::move(value);
        }
        Value result = std::int64_t{0};
        for (std::size_t index = 2; index < node.children.size(); ++index) {
          result = Evaluate(node.children[index], depth + 1);
        }
        variables_ = saved;
        return result;
      } catch (...) {
        variables_ = saved;
        throw;
      }
    }
    if (name == "and" || name == "or") {
      const bool expected = name == "and";
      for (std::size_t index = 1; index < node.children.size(); ++index) {
        const bool value =
            AsInteger(Evaluate(node.children[index], depth + 1)) != 0;
        if (value != expected) {
          return std::int64_t{value};
        }
      }
      return std::int64_t{expected};
    }
    if (name == "if") {
      if (node.children.size() != 4) {
        throw std::runtime_error("invalid descriptor if expression");
      }
      const bool condition =
          AsInteger(Evaluate(node.children[1], depth + 1)) != 0;
      return Evaluate(node.children[condition ? 2 : 3], depth + 1);
    }
    if (name == "cond") {
      for (std::size_t index = 1; index < node.children.size(); ++index) {
        const Node &clause = node.children[index];
        if (clause.kind != NodeKind::kList || clause.children.size() < 2) {
          throw std::runtime_error("invalid descriptor cond clause");
        }
        const bool is_else = clause.children[0].kind == NodeKind::kAtom &&
                             clause.children[0].text == "else";
        if (!is_else &&
            AsInteger(Evaluate(clause.children[0], depth + 1)) == 0) {
          continue;
        }
        Value result = std::int64_t{0};
        for (std::size_t body = 1; body < clause.children.size(); ++body) {
          result = Evaluate(clause.children[body], depth + 1);
        }
        return result;
      }
      return std::int64_t{0};
    }
    std::vector<Value> arguments;
    arguments.reserve(node.children.size() - 1);
    for (std::size_t index = 1; index < node.children.size(); ++index) {
      arguments.push_back(Evaluate(node.children[index], depth + 1));
    }
    if (name == "+" || name == "-" || name == "*" || name == "/" ||
        name == "binary-or" || name == "binary-and") {
      if (arguments.empty()) {
        throw std::runtime_error("descriptor arithmetic has no operands");
      }
      std::int64_t result = AsInteger(arguments[0]);
      for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::int64_t operand = AsInteger(arguments[index]);
        if (name == "binary-or") {
          result |= operand;
        } else if (name == "binary-and") {
          result &= operand;
        } else {
          result = Arithmetic(name, result, operand);
        }
      }
      return result;
    }
    if (name == "==" || name == "eq?" || name == "!=" || name == "neq?") {
      if (arguments.size() != 2) {
        throw std::runtime_error("invalid descriptor equality expression");
      }
      const bool equal = Equal(arguments[0], arguments[1]);
      return std::int64_t{(name == "==" || name == "eq?") ? equal : !equal};
    }
    if (name == "<" || name == "<=" || name == ">" || name == ">=") {
      if (arguments.size() != 2) {
        throw std::runtime_error("invalid descriptor comparison expression");
      }
      const std::int64_t left = AsInteger(arguments[0]);
      const std::int64_t right = AsInteger(arguments[1]);
      const bool result = name == "<"    ? left < right
                          : name == "<=" ? left <= right
                          : name == ">"  ? left > right
                                         : left >= right;
      return std::int64_t{result};
    }
    if (name == "not") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid descriptor not expression");
      }
      return std::int64_t{AsInteger(arguments[0]) == 0};
    }
    if (name == "bytearray?") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid descriptor bytearray predicate");
      }
      return std::int64_t{std::holds_alternative<Bytes>(arguments[0])};
    }
    if (name == "append-bytes" || name == "list") {
      Bytes result;
      for (const Value &argument : arguments) {
        const Bytes bytes = AsBytes(argument);
        result.insert(result.end(), bytes.begin(), bytes.end());
      }
      return result;
    }
    if (name == "uint32-to-uint16-bytes") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid uint16 descriptor conversion");
      }
      const auto value = static_cast<std::uint64_t>(AsInteger(arguments[0]));
      return Bytes{static_cast<std::uint8_t>(value),
                   static_cast<std::uint8_t>(value >> 8)};
    }
    if (name == "uint32->bytes" || name == "uint32-to-bytes") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid uint32 descriptor conversion");
      }
      const auto value = static_cast<std::uint64_t>(AsInteger(arguments[0]));
      return Bytes{static_cast<std::uint8_t>(value),
                   static_cast<std::uint8_t>(value >> 8),
                   static_cast<std::uint8_t>(value >> 16),
                   static_cast<std::uint8_t>(value >> 24)};
    }
    if (name == "length") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid descriptor length expression");
      }
      if (const auto *bytes = std::get_if<Bytes>(&arguments[0])) {
        return static_cast<std::int64_t>(bytes->size());
      }
      if (const auto *text = std::get_if<std::string>(&arguments[0])) {
        return static_cast<std::int64_t>(text->size());
      }
      throw std::runtime_error("descriptor length operand is invalid");
    }
    if (name == "extract-bytes") {
      if (arguments.size() != 3) {
        throw std::runtime_error("invalid descriptor byte extraction");
      }
      const Bytes bytes = AsBytes(arguments[0]);
      const std::int64_t offset = AsInteger(arguments[1]);
      const std::int64_t size = AsInteger(arguments[2]);
      if (offset < 0 || size < 0 ||
          static_cast<std::uint64_t>(offset) +
                  static_cast<std::uint64_t>(size) >
              bytes.size()) {
        throw std::runtime_error("descriptor byte extraction is out of range");
      }
      return Bytes(bytes.begin() + offset, bytes.begin() + offset + size);
    }
    if (name == "extract-byte") {
      if (arguments.size() != 2) {
        throw std::runtime_error("invalid descriptor byte extraction");
      }
      const Bytes bytes = AsBytes(arguments[0]);
      const std::int64_t offset = AsInteger(arguments[1]);
      if (offset < 0 || static_cast<std::uint64_t>(offset) >= bytes.size()) {
        throw std::runtime_error("descriptor byte extraction is out of range");
      }
      return static_cast<std::int64_t>(bytes[static_cast<std::size_t>(offset)]);
    }
    if (name == "make-list") {
      if (arguments.size() != 2) {
        throw std::runtime_error("invalid descriptor make-list expression");
      }
      const std::int64_t size = AsInteger(arguments[0]);
      if (size < 0 || size > 1'000'000) {
        throw std::runtime_error("descriptor list size is invalid");
      }
      return Bytes(static_cast<std::size_t>(size),
                   static_cast<std::uint8_t>(AsInteger(arguments[1])));
    }
    if (name == "string->bytearray") {
      if (arguments.size() != 1) {
        throw std::runtime_error("invalid descriptor string conversion");
      }
      const auto *text = std::get_if<std::string>(&arguments[0]);
      if (text == nullptr) {
        throw std::runtime_error("descriptor string conversion is invalid");
      }
      return Bytes(text->begin(), text->end());
    }
    if (name == "str") {
      std::string result;
      for (const Value &argument : arguments) {
        if (const auto *text = std::get_if<std::string>(&argument)) {
          result += *text;
        } else if (const auto *number = std::get_if<std::int64_t>(&argument)) {
          result += std::to_string(*number);
        } else {
          throw std::runtime_error("descriptor string operand is invalid");
        }
      }
      return result;
    }
    if (name == "write-log-if-debug-logging-enabled" || name == "write-log") {
      return std::int64_t{0};
    }
    return Invoke(name, arguments, depth);
  }

  const Scope &scope_;
  std::unordered_map<std::string, Value> variables_;
};

} // namespace

namespace {

struct FileSource {
  bool primary = false;
  std::filesystem::path path;
};

struct Recipe {
  std::string component;
  std::string version;
  std::filesystem::path stock_firmware;
  Scope scope;
  Node api_write;
  std::optional<Node> api_finally;
  std::optional<std::string> response_validator;
  Bindings bindings;
  std::string source_variable;
  std::size_t first_loop_index = 0;
  std::size_t loop_index = 0;
  std::size_t last_loop_index = 0;
  std::size_t expected_size = 0;
};

struct VersionField {
  std::string name;
  std::size_t offset = 0;
  std::size_t size = 0;
  bool text = false;
  std::optional<Bytes> constant;
};

struct VersionRecipe {
  std::string component;
  Bytes report;
  std::vector<VersionField> fields;
  bool bcd = false;
  std::chrono::milliseconds timeout = kDefaultVersionQueryTimeout;
  std::chrono::milliseconds command_delay{};
};

struct TransferSettings {
  std::chrono::milliseconds command_interval{};
  std::chrono::milliseconds query_timeout{};
};

struct DeviceDefinition {
  std::string descriptor;
  std::uint32_t device_id = 0;
  std::uint32_t main_id = 0;
  std::uint16_t usage_page = 0;
  std::uint16_t usage = 0;
  std::vector<std::string> recipe_keys;
  std::vector<std::uint16_t> reconnect_product_ids;
};

struct VersionDeviceDefinition {
  std::string descriptor;
  std::uint32_t device_id = 0;
  std::uint16_t usage_page = 0;
  std::uint16_t usage = 0;
  std::vector<std::string> query_keys;
};

struct Document {
  std::filesystem::path path;
  std::vector<Node> nodes;
};

const Node *FindFirstNode(const Node &node, std::string_view head) {
  if (Head(node) == head) {
    return &node;
  }
  for (const Node &child : node.children) {
    if (const Node *found = FindFirstNode(child, head)) {
      return found;
    }
  }
  return nullptr;
}

std::optional<std::uint32_t> EvaluateId(const Node &node, const Scope &scope) {
  try {
    const std::int64_t value = Evaluator(scope).Integer(node);
    if (value < 0 || static_cast<std::uint64_t>(value) >
                         std::numeric_limits<std::uint32_t>::max()) {
      return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::optional<std::uint16_t>
DirectField(const Node &device, std::string_view name, const Scope &scope) {
  for (const Node &child : device.children) {
    if (Head(child) != name || child.children.size() != 2) {
      continue;
    }
    const auto value = EvaluateId(child.children[1], scope);
    if (value && *value <= std::numeric_limits<std::uint16_t>::max()) {
      return static_cast<std::uint16_t>(*value);
    }
  }
  return std::nullopt;
}

std::vector<std::string> IdentifierTokens(std::string_view value) {
  std::vector<std::string> result;
  std::string token;
  for (const char character : value) {
    if (std::isalnum(static_cast<unsigned char>(character))) {
      token += static_cast<char>(
          std::tolower(static_cast<unsigned char>(character)));
      continue;
    }
    if (!token.empty()) {
      result.push_back(std::move(token));
      token.clear();
    }
  }
  if (!token.empty()) {
    result.push_back(std::move(token));
  }
  return result;
}

std::set<std::string> VersionTokens(std::string_view value) {
  static const std::set<std::string> ignored = {
      "bytes", "firmware", "fw", "supported", "version", "versions"};
  std::set<std::string> result;
  for (std::string &token : IdentifierTokens(value)) {
    if (!ignored.contains(token)) {
      result.insert(std::move(token));
    }
  }
  return result;
}

bool HasVersionToken(std::string_view value) {
  const std::vector<std::string> tokens = IdentifierTokens(value);
  return std::any_of(tokens.begin(), tokens.end(),
                     [](const std::string &token) {
                       return token == "version" || token == "versions";
                     });
}

bool IsReportIdField(std::string_view name) {
  const std::vector<std::string> tokens = IdentifierTokens(name);
  return std::find(tokens.begin(), tokens.end(), "report") != tokens.end() &&
         std::find(tokens.begin(), tokens.end(), "id") != tokens.end();
}

std::string SupportedVersion(const Scope &scope, std::string_view component) {
  const std::set<std::string> component_tokens = VersionTokens(component);
  std::optional<std::string> best;
  std::optional<std::string> generic;
  std::size_t best_score = 0;
  bool ambiguous = false;
  bool generic_ambiguous = false;
  for (const auto &[name, function] : scope.functions) {
    const std::vector<std::string> name_tokens = IdentifierTokens(name);
    if (!function.parameters.empty() || !HasVersionToken(name) ||
        std::find(name_tokens.begin(), name_tokens.end(), "supported") ==
            name_tokens.end()) {
      continue;
    }
    try {
      const std::string value =
          Evaluator(scope).String({NodeKind::kAtom, 0, name, {}});
      const std::set<std::string> function_tokens = VersionTokens(name);
      if (function_tokens.empty()) {
        if (!generic) {
          generic = value;
        } else if (*generic != value) {
          generic_ambiguous = true;
        }
      }
      const std::size_t score =
          std::count_if(function_tokens.begin(), function_tokens.end(),
                        [&component_tokens](const std::string &token) {
                          return component_tokens.contains(token);
                        });
      if (score > best_score) {
        best = value;
        best_score = score;
        ambiguous = false;
      } else if (score == best_score && score != 0 && best && *best != value) {
        ambiguous = true;
      }
    } catch (const std::exception &) {
    }
  }
  if (best_score != 0 && best && !ambiguous) {
    return *best;
  }
  if (generic && !generic_ambiguous) {
    return *generic;
  }
  return "unknown";
}

std::optional<std::string> FindResponseValidator(const Node &api_finally,
                                                 const Scope &scope) {
  std::set<std::string> candidates;
  std::function<void(const Node &)> visit = [&](const Node &node) {
    const std::string_view head = Head(node);
    if (!head.empty()) {
      const auto function = scope.functions.find(std::string(head));
      if (function != scope.functions.end() &&
          function->second.parameters.size() == 1 &&
          std::any_of(function->second.body.begin(),
                      function->second.body.end(), [](const Node &body) {
                        return ContainsAtom(body, "extract-byte") ||
                               ContainsAtom(body, "extract-bytes");
                      })) {
        candidates.insert(function->first);
      }
    }
    for (const Node &child : node.children) {
      visit(child);
    }
  };
  visit(api_finally);
  if (candidates.size() != 1) {
    return std::nullopt;
  }
  return *candidates.begin();
}

const Node *FindFirmwareApi(const Node &device, const Scope &scope) {
  for (const Node *api : FindReachableNodes(device, "api", scope)) {
    if (api->children.size() >= 2 && api->children[1].kind == NodeKind::kAtom &&
        api->children[1].text == "fw_update") {
      return api;
    }
  }
  return nullptr;
}

Bindings ApiBindings(const Node &api) {
  Bindings result;
  const Node *bindings = FindFirstNode(api, "api-let");
  if (bindings == nullptr) {
    bindings = FindFirstNode(api, "api-let*");
  }
  if (bindings == nullptr) {
    return result;
  }
  for (std::size_t index = 1; index < bindings->children.size(); ++index) {
    const Node &binding = bindings->children[index];
    if (binding.kind == NodeKind::kList && binding.children.size() == 2 &&
        binding.children[0].kind == NodeKind::kAtom) {
      result.emplace_back(binding.children[0].text, binding.children[1]);
    }
  }
  return result;
}

std::unordered_map<std::string, FileSource>
FirmwareSources(const Bindings &bindings, const Scope &scope,
                const std::filesystem::path &engine) {
  std::unordered_map<std::string, FileSource> result;
  for (const auto &[name, expression] : bindings) {
    if (Head(expression) != "read-engine-file" ||
        expression.children.size() != 2) {
      continue;
    }
    const Node &source = expression.children[1];
    if (source.kind == NodeKind::kAtom && source.text == "payload") {
      result.emplace(name, FileSource{true, {}});
      continue;
    }
    try {
      const std::filesystem::path relative = Evaluator(scope).String(source);
      result.emplace(name, FileSource{false, engine / relative});
    } catch (const std::exception &) {
    }
  }
  return result;
}

std::optional<std::string>
LoopSource(const Node &loop,
           const std::unordered_map<std::string, FileSource> &sources) {
  std::set<std::string> matches;
  for (const Node *extract : FindNodes(loop, "extract-bytes")) {
    if (extract->children.size() >= 2 &&
        extract->children[1].kind == NodeKind::kAtom &&
        sources.contains(extract->children[1].text)) {
      matches.insert(extract->children[1].text);
    }
  }
  if (matches.size() != 1) {
    return std::nullopt;
  }
  return *matches.begin();
}

void PopulateBindings(Evaluator &evaluator, const Bindings &bindings,
                      const std::string &source_variable,
                      const Bytes *firmware) {
  if (firmware != nullptr) {
    evaluator.Set(source_variable, *firmware);
  }
  for (const auto &[name, expression] : bindings) {
    if (Head(expression) == "read-engine-file") {
      continue;
    }
    try {
      evaluator.Set(name, evaluator.Evaluate(expression));
    } catch (const std::exception &) {
    }
  }
}

std::size_t ExpectedSize(const Node &loop, const std::string &source,
                         const Scope &scope, const Bindings &bindings,
                         const std::vector<Node> &tail) {
  if (loop.children.size() < 2) {
    throw std::runtime_error("firmware chunk loop has no iteration count");
  }
  Evaluator evaluator(scope);
  PopulateBindings(evaluator, bindings, source, nullptr);
  const std::int64_t count = evaluator.Integer(loop.children[1]);
  if (count <= 0 || count > 10'000'000) {
    throw std::runtime_error("firmware chunk loop count is invalid");
  }
  std::size_t maximum = 0;
  for (const Node *extract : FindNodes(loop, "extract-bytes")) {
    if (extract->children.size() != 4 ||
        extract->children[1].kind != NodeKind::kAtom ||
        extract->children[1].text != source) {
      continue;
    }
    evaluator.Set("loopcount", std::int64_t{0});
    const std::int64_t first = evaluator.Integer(extract->children[2]);
    const std::int64_t size = evaluator.Integer(extract->children[3]);
    evaluator.Set("loopcount", std::int64_t{1});
    const std::int64_t second = evaluator.Integer(extract->children[2]);
    if (first < 0 || size <= 0 || second < first) {
      throw std::runtime_error("firmware chunk offsets are invalid");
    }
    const std::uint64_t start = static_cast<std::uint64_t>(first);
    const std::uint64_t iterations = static_cast<std::uint64_t>(count - 1);
    const std::uint64_t stride = static_cast<std::uint64_t>(second - first);
    const std::uint64_t chunk_size = static_cast<std::uint64_t>(size);
    if ((stride != 0 &&
         iterations >
             (std::numeric_limits<std::uint64_t>::max() - start) / stride) ||
        chunk_size > std::numeric_limits<std::uint64_t>::max() - start -
                         iterations * stride) {
      throw std::runtime_error("firmware chunk range is too large");
    }
    const std::uint64_t end = start + iterations * stride + chunk_size;
    if (end > std::numeric_limits<std::size_t>::max()) {
      throw std::runtime_error("firmware chunk range is too large");
    }
    maximum = std::max(maximum, static_cast<std::size_t>(end));
  }
  evaluator.Set("loopcount", count);
  for (const Node &node : tail) {
    for (const Node *extract : FindNodes(node, "extract-bytes")) {
      if (extract->children.size() != 4 ||
          extract->children[1].kind != NodeKind::kAtom ||
          extract->children[1].text != source) {
        continue;
      }
      const std::int64_t offset = evaluator.Integer(extract->children[2]);
      const std::int64_t size = evaluator.Integer(extract->children[3]);
      if (offset < 0 || size <= 0) {
        throw std::runtime_error("firmware tail chunk range is invalid");
      }
      const std::uint64_t end =
          static_cast<std::uint64_t>(offset) + static_cast<std::uint64_t>(size);
      if (end > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("firmware tail chunk range is too large");
      }
      maximum = std::max(maximum, static_cast<std::size_t>(end));
    }
  }
  if (maximum == 0) {
    throw std::runtime_error("firmware loop has no byte extraction");
  }
  return maximum;
}

bool IsChunk(const Node &node) {
  const std::string_view head = Head(node);
  return head == "chunk" || head == "write-chunk" || head == "read-chunk";
}

bool IsHidChunk(const Node &node) {
  return IsChunk(node) && node.children.size() >= 4 &&
         node.children[1].kind == NodeKind::kAtom &&
         (node.children[1].text == "HIDIO" ||
          node.children[1].text == "HIDIONOFAIL");
}

bool ApplyTransferSettings(const Node &node, Evaluator &evaluator,
                           TransferSettings &settings) {
  if (!IsChunk(node) || node.children.size() < 4 ||
      node.children[1].kind != NodeKind::kAtom ||
      node.children[1].text != "HIDCONFIG") {
    return false;
  }
  const Node &payload = node.children[3];
  if (payload.kind != NodeKind::kList || payload.delimiter != '[' ||
      payload.children.empty()) {
    throw std::runtime_error("descriptor HID configuration is invalid");
  }
  const Bytes interval = evaluator.ByteArray(payload.children[0]);
  if (interval.size() != 4) {
    throw std::runtime_error("descriptor HID command interval is invalid");
  }
  const std::uint32_t interval_ms = ReadLe32(interval, 0);
  if (interval_ms > kMaximumCommandIntervalMs) {
    throw std::runtime_error("descriptor HID command interval is too long");
  }
  settings.command_interval = std::chrono::milliseconds(interval_ms);
  if (payload.children.size() >= 3) {
    const Bytes timeout = evaluator.ByteArray(payload.children[2]);
    if (timeout.size() != 4) {
      throw std::runtime_error("descriptor HID timeout is invalid");
    }
    const std::uint32_t timeout_ms = ReadLe32(timeout, 0);
    if (timeout_ms > kMaximumCommandTimeoutMs) {
      throw std::runtime_error("descriptor HID timeout is too long");
    }
    settings.query_timeout = std::chrono::milliseconds(timeout_ms);
  }
  return true;
}

std::filesystem::path
FindPrimaryFirmware(const std::filesystem::path &engine, std::uint32_t main_id,
                    std::size_t expected_size,
                    const std::set<std::filesystem::path> &explicit_files) {
  const std::filesystem::path directory =
      engine / "firmware" / std::to_string(main_id);
  std::vector<std::filesystem::path> candidates;
  std::error_code error;
  for (std::filesystem::directory_iterator iterator(directory, error), end;
       !error && iterator != end; iterator.increment(error)) {
    if (!iterator->is_regular_file() ||
        iterator->path().extension() != ".bin" ||
        explicit_files.contains(iterator->path().lexically_normal()) ||
        iterator->file_size() != expected_size) {
      continue;
    }
    candidates.push_back(iterator->path());
  }
  if (error || candidates.size() != 1) {
    throw std::runtime_error("primary firmware file is absent or ambiguous");
  }
  return candidates.front();
}

std::optional<UpdateAction> CompileChunk(const Node &node,
                                         Evaluator &evaluator) {
  if (!IsChunk(node) || node.children.size() < 4 ||
      node.children[1].kind != NodeKind::kAtom) {
    return std::nullopt;
  }
  const std::string &channel = node.children[1].text;
  if (channel == "HIDSLEEP") {
    const Bytes encoded = evaluator.ByteArray(node.children[3]);
    if (encoded.size() < 4) {
      throw std::runtime_error("descriptor sleep payload is truncated");
    }
    const std::uint32_t delay = static_cast<std::uint32_t>(encoded[0]) |
                                (static_cast<std::uint32_t>(encoded[1]) << 8) |
                                (static_cast<std::uint32_t>(encoded[2]) << 16) |
                                (static_cast<std::uint32_t>(encoded[3]) << 24);
    if (delay > kMaximumSleepMs) {
      throw std::runtime_error("descriptor sleep duration is too long");
    }
    return UpdateAction{
        UpdateActionType::kSleep, {}, std::chrono::milliseconds(delay), {}, {}};
  }
  if (channel != "HIDIO" && channel != "HIDIONOFAIL") {
    return std::nullopt;
  }
  const std::int64_t report_size = evaluator.Integer(node.children[2]);
  Bytes report = evaluator.ByteArray(node.children[3]);
  if (report_size <= 0 ||
      report_size > static_cast<std::int64_t>(kMaximumHidReportSize) ||
      report.size() > static_cast<std::size_t>(report_size)) {
    throw std::runtime_error("descriptor HID report size is invalid");
  }
  report.resize(static_cast<std::size_t>(report_size));
  UpdateActionType type = UpdateActionType::kWrite;
  if (Head(node) == "read-chunk") {
    type = UpdateActionType::kQuery;
  } else if (channel == "HIDIONOFAIL") {
    type = UpdateActionType::kWriteNoFail;
  }
  return UpdateAction{type, std::move(report), {}, {}, {}};
}

struct ParsedVersionFields {
  Bytes constants;
  std::vector<VersionField> fields;
};

ParsedVersionFields ParseVersionFields(const Node &section,
                                       Evaluator &evaluator,
                                       bool require_constants) {
  ParsedVersionFields result;
  std::size_t offset = 0;
  for (const Node &field : section.children) {
    const std::string_view head = Head(field);
    if ((field.kind == NodeKind::kAtom &&
         field.text == section.children[0].text) ||
        head == "unaligned") {
      continue;
    }
    if (head != "field") {
      throw std::runtime_error(
          "firmware version structure layout is unsupported");
    }
    if (field.children.size() < 3 ||
        field.children[1].kind != NodeKind::kAtom ||
        field.children[2].kind != NodeKind::kAtom) {
      throw std::runtime_error("firmware version field is invalid");
    }
    const std::string &name = field.children[1].text;
    const std::string &type = field.children[2].text;
    std::size_t size = type == "uint8"    ? 1
                       : type == "uint16" ? 2
                       : type == "uint32" ? 4
                                          : 0;
    const Node *constant = nullptr;
    for (std::size_t index = 3; index < field.children.size(); ++index) {
      const Node &modifier = field.children[index];
      const std::string_view modifier_name = Head(modifier);
      if ((modifier_name == "size" || modifier_name == "repeat") &&
          modifier.children.size() == 2) {
        const std::int64_t count = evaluator.Integer(modifier.children[1]);
        if (count <= 0 ||
            count > static_cast<std::int64_t>(kMaximumHidReportSize)) {
          throw std::runtime_error("firmware version field size is invalid");
        }
        if (type == "bytearray") {
          size = static_cast<std::size_t>(count);
        } else if (size != 0) {
          size *= static_cast<std::size_t>(count);
        }
      } else if (modifier_name == "constant" && modifier.children.size() == 2) {
        constant = &modifier.children[1];
      }
    }
    if (size == 0 || offset > kMaximumHidReportSize ||
        size > kMaximumHidReportSize - offset) {
      throw std::runtime_error(
          "firmware version field type or layout is unsupported");
    }
    std::optional<Bytes> encoded_constant;
    if (constant != nullptr) {
      Bytes encoded;
      const Value value = evaluator.Evaluate(*constant);
      if (const auto *number = std::get_if<std::int64_t>(&value)) {
        const auto encoded_number = static_cast<std::uint64_t>(*number);
        encoded.resize(size);
        for (std::size_t index = 0; index < size; ++index) {
          encoded[index] =
              index < sizeof(encoded_number)
                  ? static_cast<std::uint8_t>(encoded_number >> (index * 8))
                  : static_cast<std::uint8_t>(*number < 0 ? 0xFF : 0x00);
        }
      } else if (const auto *bytes = std::get_if<Bytes>(&value)) {
        encoded = *bytes;
      } else if (const auto *text = std::get_if<std::string>(&value)) {
        encoded.assign(text->begin(), text->end());
      }
      if (encoded.size() != size) {
        throw std::runtime_error(
            "firmware version field constant has the wrong size");
      }
      encoded_constant = std::move(encoded);
    }
    if (require_constants) {
      if (!encoded_constant) {
        throw std::runtime_error(
            "firmware version request has a nonconstant field");
      }
      result.constants.insert(result.constants.end(), encoded_constant->begin(),
                              encoded_constant->end());
    } else {
      result.fields.push_back({name, offset, size, type == "bytearray",
                               std::move(encoded_constant)});
    }
    offset += size;
  }
  if (offset == 0) {
    throw std::runtime_error("firmware version structure has no fields");
  }
  return result;
}

std::optional<VersionRecipe> CompileVersionRecipe(const Node &api,
                                                  const Node &structure,
                                                  const Scope &scope,
                                                  std::string component) {
  const Node *api_read = FindFirstNode(api, "api-read");
  if (api_read == nullptr || api_read->children.size() < 3 ||
      api_read->children[1].kind != NodeKind::kAtom ||
      api_read->children[1].text != "HID") {
    return std::nullopt;
  }
  const Node *chunk = nullptr;
  for (std::size_t index = 2; index < api_read->children.size(); ++index) {
    if (IsChunk(api_read->children[index])) {
      if (chunk != nullptr) {
        return std::nullopt;
      }
      chunk = &api_read->children[index];
    }
  }
  if (chunk == nullptr) {
    return std::nullopt;
  }

  const Node *outgoing = FindFirstNode(structure, "outgoing");
  const Node *incoming = FindFirstNode(structure, "incoming");
  if (outgoing == nullptr || incoming == nullptr) {
    return std::nullopt;
  }
  Evaluator evaluator(scope);
  const ParsedVersionFields request =
      ParseVersionFields(*outgoing, evaluator, true);
  const ParsedVersionFields response =
      ParseVersionFields(*incoming, evaluator, false);
  evaluator.Set("payload", request.constants);
  const auto compiled = CompileChunk(*chunk, evaluator);
  if (!compiled || compiled->report.empty()) {
    return std::nullopt;
  }

  VersionRecipe recipe;
  recipe.component = std::move(component);
  recipe.report = compiled->report;
  recipe.fields = response.fields;
  try {
    recipe.bcd =
        Evaluator(scope).Integer({NodeKind::kAtom, 0, "fw_is_bcd", {}}) != 0;
  } catch (const std::exception &) {
  }
  try {
    const std::int64_t timeout =
        Evaluator(scope).Integer({NodeKind::kAtom, 0, "max-usb-timeout", {}});
    if (timeout > 0 &&
        timeout <= static_cast<std::int64_t>(kMaximumCommandTimeoutMs)) {
      recipe.timeout = std::chrono::milliseconds(timeout);
    }
  } catch (const std::exception &) {
  }
  try {
    const std::int64_t delay = Evaluator(scope).Integer(
        {NodeKind::kAtom, 0, "time-between-commands", {}});
    if (delay >= 0 &&
        delay <= static_cast<std::int64_t>(kMaximumCommandIntervalMs)) {
      recipe.command_delay = std::chrono::milliseconds(delay);
    }
  } catch (const std::exception &) {
  }
  return recipe;
}

void AppendChunk(const Node &node, Evaluator &evaluator,
                 TransferSettings &settings,
                 std::vector<UpdateAction> &actions) {
  if (ApplyTransferSettings(node, evaluator, settings)) {
    return;
  }
  auto compiled = CompileChunk(node, evaluator);
  if (!compiled) {
    if (IsChunk(node) && node.children.size() >= 2 &&
        node.children[1].kind == NodeKind::kAtom &&
        node.children[1].text != "SSFWSTATUS") {
      throw std::runtime_error(
          "descriptor uses an unsupported update channel: " +
          node.children[1].text);
    }
    return;
  }
  if (compiled->type == UpdateActionType::kQuery) {
    compiled->timeout = settings.query_timeout;
  }
  actions.push_back(*compiled);
  if (compiled->type != UpdateActionType::kSleep &&
      settings.command_interval.count() > 0) {
    actions.push_back(
        {UpdateActionType::kSleep, {}, settings.command_interval, {}, {}});
  }
}

std::optional<Bytes> RawReport(const Node &call, Evaluator &evaluator) {
  if ((Head(call) != "raw-read-from-device" &&
       Head(call) != "raw-write-to-device") ||
      call.children.size() < 2) {
    return std::nullopt;
  }
  Bytes wrapper = evaluator.ByteArray(call.children.back());
  if (wrapper.size() < 8 || wrapper[4] == 0 ||
      wrapper.size() < 8 + static_cast<std::size_t>(wrapper[4])) {
    return std::nullopt;
  }
  return Bytes(wrapper.begin() + 8, wrapper.begin() + 8 + wrapper[4]);
}

std::size_t FirmwareSetupStart(const Node &api_write, std::size_t loop_index) {
  std::optional<std::size_t> erase;
  for (std::size_t index = loop_index; index > 0;) {
    --index;
    if (IsHidChunk(api_write.children[index])) {
      erase = index;
      break;
    }
    if (Head(api_write.children[index]) == "chunk-loop") {
      throw std::runtime_error("firmware loop has no preceding erase report");
    }
  }
  if (!erase) {
    throw std::runtime_error("firmware loop has no preceding erase report");
  }
  std::size_t start = *erase;
  if (start > 0 && IsChunk(api_write.children[start - 1]) &&
      api_write.children[start - 1].children.size() >= 2 &&
      api_write.children[start - 1].children[1].kind == NodeKind::kAtom &&
      api_write.children[start - 1].children[1].text == "HIDSLEEP") {
    --start;
  }
  return start;
}

bool IsGenericVersionToken(const std::string &token) {
  static const std::set<std::string> generic = {
      "actual", "bytearray", "bytes", "firmware", "fw",
      "str",    "string",    "ver",   "version",  "versions"};
  return generic.contains(token);
}

std::string JoinTokens(const std::vector<std::string> &tokens) {
  std::string result;
  for (const std::string &token : tokens) {
    if (!result.empty()) {
      result += '_';
    }
    result += token;
  }
  return result;
}

std::string VersionComponent(std::string_view name,
                             std::string_view fallback = {}) {
  std::vector<std::string> component;
  for (std::string &token : IdentifierTokens(name)) {
    if (!IsGenericVersionToken(token)) {
      component.push_back(std::move(token));
    }
  }
  if (!component.empty()) {
    return JoinTokens(component);
  }
  return fallback.empty() ? std::string(name) : std::string(fallback);
}

struct VersionPart {
  std::size_t token_index = 0;
  unsigned order = 0;
  std::string name;
};

std::optional<VersionPart>
FindVersionPart(const std::vector<std::string> &tokens) {
  static const std::map<std::string, unsigned> named_parts = {
      {"major", 0}, {"high", 0},    {"minor", 1},   {"mid", 1},   {"patch", 2},
      {"low", 2},   {"variant", 2}, {"varient", 2}, {"build", 3},
  };
  for (std::size_t index = 0; index < tokens.size(); ++index) {
    if (const auto found = named_parts.find(tokens[index]);
        found != named_parts.end()) {
      return VersionPart{index, found->second, tokens[index]};
    }
  }
  if (tokens.empty()) {
    return std::nullopt;
  }
  const auto numeric = ParseInteger(tokens.back());
  if (!numeric || *numeric <= 0 ||
      *numeric >
          static_cast<std::int64_t>(std::numeric_limits<unsigned>::max())) {
    return std::nullopt;
  }
  return VersionPart{tokens.size() - 1, static_cast<unsigned>(*numeric - 1),
                     tokens.back()};
}

std::string VersionFieldComponent(const std::vector<std::string> &tokens,
                                  std::optional<std::size_t> part_index,
                                  std::string_view fallback) {
  std::vector<std::string> component;
  for (std::size_t index = 0; index < tokens.size(); ++index) {
    if (part_index && index == *part_index) {
      continue;
    }
    if (!IsGenericVersionToken(tokens[index])) {
      component.push_back(tokens[index]);
    }
  }
  return component.empty() ? std::string(fallback) : JoinTokens(component);
}

std::string HexBytes(const Bytes &bytes, std::size_t offset, std::size_t size) {
  std::ostringstream result;
  result << "0x" << std::hex << std::setfill('0');
  for (std::size_t index = 0; index < size; ++index) {
    result << std::setw(2) << static_cast<unsigned>(bytes[offset + index]);
  }
  return result.str();
}

} // namespace

class Catalog::Impl {
public:
  explicit Impl(const std::filesystem::path &program_directory)
      : engine_directory_(program_directory / "apps" / "engine") {
    const std::filesystem::path engine_executable =
        engine_directory_ / "SteelSeriesEngine.exe";
    const std::filesystem::path specifications =
        engine_directory_ / "deviceSpecifications";
    if (!std::filesystem::is_regular_file(engine_executable) ||
        !std::filesystem::is_directory(specifications)) {
      throw std::runtime_error(
          "program directory has no apps/engine GG payload: " +
          program_directory.string());
    }
    const Bytes password =
        ExtractDescriptorPassword(ReadFile(engine_executable));
    std::vector<Document> documents;
    for (const auto &entry :
         std::filesystem::directory_iterator(specifications)) {
      if (!entry.is_regular_file() || entry.path().extension() != ".edevice") {
        continue;
      }
      try {
        const Bytes plaintext =
            DecryptDescriptor(ReadFile(entry.path()), password);
        documents.push_back(
            {entry.path(),
             Parser(std::string_view(
                        reinterpret_cast<const char *>(plaintext.data()),
                        plaintext.size()))
                 .Parse()});
      } catch (const std::exception &) {
      }
    }
    if (documents.empty()) {
      throw std::runtime_error("GG contains no readable device descriptors");
    }

    Scope global;
    for (const Document &document : documents) {
      for (const Node &node : document.nodes) {
        AddDefinition(node, global);
      }
    }
    for (const Document &document : documents) {
      CompileDocument(document, global);
      CompileVersionDocument(document, global);
    }
    for (DeviceDefinition &device : devices_) {
      std::set<std::uint16_t> reconnect;
      for (const DeviceDefinition &candidate : devices_) {
        if (candidate.descriptor == device.descriptor &&
            candidate.main_id == device.main_id) {
          reconnect.insert(static_cast<std::uint16_t>(candidate.device_id));
        }
      }
      device.reconnect_product_ids.assign(reconnect.begin(), reconnect.end());
    }
  }

  std::vector<FirmwareTarget> DiscoverTargets() const {
    const std::vector<DeviceInfo> hardware = ListFirmwareDevices();
    std::vector<FirmwareTarget> targets;
    std::map<std::pair<std::uint16_t, std::uint16_t>, std::size_t> indices;
    for (const DeviceInfo &endpoint : hardware) {
      const auto pair = std::pair{endpoint.vendor_id, endpoint.product_id};
      const std::size_t index = indices[pair]++;
      std::vector<const DeviceDefinition *> matches;
      for (const DeviceDefinition &definition : devices_) {
        if (static_cast<std::uint16_t>(definition.device_id >> 16) ==
                endpoint.vendor_id &&
            static_cast<std::uint16_t>(definition.device_id) ==
                endpoint.product_id &&
            definition.usage_page == endpoint.usage_page &&
            definition.usage == endpoint.usage) {
          matches.push_back(&definition);
        }
      }
      if (matches.empty()) {
        continue;
      }
      if (matches.size() != 1) {
        throw std::runtime_error(
            "GG descriptors ambiguously match one connected HID interface");
      }
      const DeviceDefinition &definition = *matches.front();
      const std::string physical = FormatDeviceAddress(endpoint, index);
      for (const std::string &key : definition.recipe_keys) {
        const Recipe &recipe = recipes_.at(key);
        const std::string product =
            endpoint.product.empty() ? definition.descriptor : endpoint.product;
        targets.push_back({physical, recipe.component,
                           product + " - " + recipe.component, endpoint,
                           recipe.stock_firmware, recipe.expected_size,
                           definition.reconnect_product_ids, key});
      }
    }
    std::sort(targets.begin(), targets.end(),
              [](const FirmwareTarget &left, const FirmwareTarget &right) {
                return std::tie(left.device_address, left.component) <
                       std::tie(right.device_address, right.component);
              });
    return targets;
  }

  FirmwareTarget ResolveTarget(const std::string &device_address,
                               const std::string &source_sha256) const {
    const std::vector<FirmwareTarget> targets = DiscoverTargets();
    const bool path_selected =
        std::any_of(targets.begin(), targets.end(),
                    [&device_address](const FirmwareTarget &target) {
                      return target.device.path == device_address;
                    });
    std::optional<FirmwareTarget> result;
    bool device_found = false;
    for (const FirmwareTarget &target : targets) {
      if ((path_selected && target.device.path != device_address) ||
          (!path_selected && target.device_address != device_address)) {
        continue;
      }
      device_found = true;
      if (!path_selected && target.device.serial.empty()) {
        const auto matching_endpoints = std::count_if(
            targets.begin(), targets.end(),
            [&target](const FirmwareTarget &candidate) {
              return candidate.device.vendor_id == target.device.vendor_id &&
                     candidate.device.product_id == target.device.product_id &&
                     candidate.device.path != target.device.path;
            });
        if (matching_endpoints != 0) {
          throw std::runtime_error(
              "target address is ambiguous; use the HID path from dev-list");
        }
      }
      if (Sha256Hex(ReadFile(target.stock_firmware)) != source_sha256) {
        continue;
      }
      if (result) {
        throw std::runtime_error(
            "firmware matches multiple GG components for target: " +
            device_address);
      }
      result = target;
    }
    if (!result) {
      if (!device_found) {
        throw std::runtime_error("target address is not present: " +
                                 device_address);
      }
      throw std::runtime_error(
          "firmware does not match any GG stock component for target: " +
          device_address);
    }
    return *result;
  }

  std::vector<FirmwareIdentity>
  IdentifyFirmware(const std::string &source_sha256) const {
    std::vector<FirmwareIdentity> identities;
    std::set<std::tuple<std::string, std::string, std::string,
                        std::filesystem::path>>
        unique;
    for (const auto &[key, recipe] : recipes_) {
      const std::size_t separator = key.find(':');
      const std::string model =
          separator == std::string::npos ? key : key.substr(0, separator);
      if (Sha256Hex(ReadFile(recipe.stock_firmware)) != source_sha256 ||
          !unique
               .emplace(model, recipe.component, recipe.version,
                        recipe.stock_firmware)
               .second) {
        continue;
      }
      identities.push_back(
          {model, recipe.component, recipe.version, recipe.stock_firmware});
    }
    std::sort(identities.begin(), identities.end(),
              [](const FirmwareIdentity &left, const FirmwareIdentity &right) {
                return std::tie(left.model, left.component, left.version,
                                left.stock_firmware) <
                       std::tie(right.model, right.component, right.version,
                                right.stock_firmware);
              });
    return identities;
  }

  FirmwareVersionTarget
  ResolveVersionTarget(const std::string &device_address) const {
    std::map<std::pair<std::uint16_t, std::uint16_t>, std::size_t> indices;
    std::optional<FirmwareVersionTarget> result;
    bool address_found = false;
    for (const DeviceInfo &endpoint : ListFirmwareDevices()) {
      const auto pair = std::pair{endpoint.vendor_id, endpoint.product_id};
      const std::string address =
          FormatDeviceAddress(endpoint, indices[pair]++);
      if (device_address != address && device_address != endpoint.path) {
        continue;
      }
      address_found = true;
      std::vector<const VersionDeviceDefinition *> matches;
      for (const VersionDeviceDefinition &definition : version_devices_) {
        if (static_cast<std::uint16_t>(definition.device_id >> 16) ==
                endpoint.vendor_id &&
            static_cast<std::uint16_t>(definition.device_id) ==
                endpoint.product_id &&
            definition.usage_page == endpoint.usage_page &&
            definition.usage == endpoint.usage) {
          matches.push_back(&definition);
        }
      }
      if (matches.size() != 1 || result) {
        throw std::runtime_error(
            matches.empty()
                ? "GG descriptor exposes no readable firmware version for "
                  "target: " +
                      device_address
                : "GG descriptors ambiguously match firmware version target: " +
                      device_address);
      }
      FirmwareVersionTarget target;
      target.product = endpoint.product.empty() ? matches.front()->descriptor
                                                : endpoint.product;
      target.device = endpoint;
      for (const std::string &key : matches.front()->query_keys) {
        const VersionRecipe &recipe = version_recipes_.at(key);
        target.queries.push_back(
            {key, recipe.report, recipe.timeout, recipe.command_delay});
      }
      result = std::move(target);
    }
    if (!result) {
      throw std::runtime_error(
          address_found
              ? "GG descriptor exposes no readable firmware version for "
                "target: " +
                    device_address
              : "target address is not present: " + device_address);
    }
    return *result;
  }

  std::vector<FirmwareVersion> DecodeVersion(const FirmwareVersionQuery &query,
                                             const Bytes &response) const {
    const auto found = version_recipes_.find(query.query_key);
    if (found == version_recipes_.end()) {
      throw std::runtime_error("firmware version query no longer exists");
    }
    const VersionRecipe &recipe = found->second;
    Bytes normalized_response = response;
    if (!recipe.fields.empty() && recipe.fields.front().offset == 0 &&
        IsReportIdField(recipe.fields.front().name) &&
        recipe.fields.front().constant &&
        *recipe.fields.front().constant == Bytes{0}) {
      normalized_response.insert(normalized_response.begin(), 0);
    }
    for (const VersionField &field : recipe.fields) {
      if (field.offset > normalized_response.size() ||
          field.size > normalized_response.size() - field.offset) {
        throw std::runtime_error("firmware version response is truncated");
      }
      if (field.constant &&
          !std::equal(field.constant->begin(), field.constant->end(),
                      normalized_response.begin() +
                          static_cast<std::ptrdiff_t>(field.offset))) {
        throw std::runtime_error(
            "firmware version response field " + field.name + " is " +
            HexBytes(normalized_response, field.offset, field.size) +
            ", expected " +
            HexBytes(*field.constant, 0, field.constant->size()) +
            " (received " + std::to_string(response.size()) + " bytes)");
      }
    }

    auto read_integer = [&normalized_response](const VersionField &field) {
      if (field.size > sizeof(std::uint64_t)) {
        throw std::runtime_error("firmware version integer field is too large");
      }
      std::uint64_t value = 0;
      for (std::size_t index = 0; index < field.size; ++index) {
        value |= static_cast<std::uint64_t>(
                     normalized_response[field.offset + index])
                 << (index * 8);
      }
      return value;
    };
    auto converted_integer = [&recipe,
                              &read_integer](const VersionField &field) {
      const std::uint64_t value = read_integer(field);
      if (!recipe.bcd || field.size != 1) {
        return value;
      }
      return ((value >> 4) & 0x0F) * 10 + (value & 0x0F);
    };

    std::vector<FirmwareVersion> versions;
    for (const VersionField &field : recipe.fields) {
      if (!field.text || field.constant) {
        continue;
      }
      const auto begin = normalized_response.begin() +
                         static_cast<std::ptrdiff_t>(field.offset);
      const auto end = begin + static_cast<std::ptrdiff_t>(field.size);
      const auto terminator = std::find(begin, end, std::uint8_t{0});
      const bool zero_padded =
          terminator == end ||
          std::all_of(terminator, end,
                      [](std::uint8_t value) { return value == 0; });
      std::string version;
      if (zero_padded && terminator != begin &&
          std::all_of(begin, terminator, [](std::uint8_t value) {
            return std::isprint(static_cast<unsigned char>(value));
          })) {
        version.assign(begin, terminator);
        while (!version.empty() &&
               std::isspace(static_cast<unsigned char>(version.back()))) {
          version.pop_back();
        }
      }
      if (version.empty()) {
        version = HexBytes(normalized_response, field.offset, field.size);
      }
      versions.push_back(
          {VersionComponent(field.name, recipe.component), std::move(version)});
    }

    struct NumericPart {
      const VersionField *field = nullptr;
      VersionPart part;
    };
    struct NumericGroup {
      std::string component;
      std::vector<NumericPart> parts;
    };
    std::vector<NumericGroup> groups;
    for (const VersionField &field : recipe.fields) {
      if (field.text || field.constant) {
        continue;
      }
      const std::vector<std::string> tokens = IdentifierTokens(field.name);
      const std::optional<VersionPart> part = FindVersionPart(tokens);
      if (!part) {
        continue;
      }
      const std::string component =
          VersionFieldComponent(tokens, part->token_index, recipe.component);
      auto group = std::find_if(groups.begin(), groups.end(),
                                [&component](const NumericGroup &candidate) {
                                  return candidate.component == component;
                                });
      if (group == groups.end()) {
        groups.push_back({component, {}});
        group = std::prev(groups.end());
      }
      group->parts.push_back({&field, *part});
    }

    std::set<const VersionField *> grouped_fields;
    for (NumericGroup &group : groups) {
      if (group.parts.size() < 2) {
        continue;
      }
      std::sort(group.parts.begin(), group.parts.end(),
                [](const NumericPart &left, const NumericPart &right) {
                  return left.part.order < right.part.order;
                });
      const auto duplicate = std::adjacent_find(
          group.parts.begin(), group.parts.end(),
          [](const NumericPart &left, const NumericPart &right) {
            return left.part.order == right.part.order;
          });
      if (duplicate != group.parts.end()) {
        continue;
      }
      std::string version;
      for (const NumericPart &part : group.parts) {
        if (!version.empty()) {
          version += '.';
        }
        version += std::to_string(converted_integer(*part.field));
        grouped_fields.insert(part.field);
      }
      versions.push_back({group.component, std::move(version)});
    }

    for (const VersionField &field : recipe.fields) {
      if (field.text || field.constant || grouped_fields.contains(&field)) {
        continue;
      }
      const std::vector<std::string> tokens = IdentifierTokens(field.name);
      const std::optional<VersionPart> part = FindVersionPart(tokens);
      const bool named_version = std::any_of(
          tokens.begin(), tokens.end(), [](const std::string &token) {
            return token == "ver" || token == "version" || token == "versions";
          });
      if (!part && !named_version) {
        continue;
      }
      std::string component = VersionFieldComponent(
          tokens, part ? std::optional(part->token_index) : std::nullopt,
          recipe.component);
      if (part) {
        component += '_';
        component += part->name;
      }
      versions.push_back(
          {std::move(component), std::to_string(converted_integer(field))});
    }
    if (versions.empty()) {
      throw std::runtime_error(
          "firmware version response format is unsupported");
    }
    return versions;
  }

  std::vector<UpdateAction> BuildUpdate(const FirmwareTarget &target,
                                        const Bytes &firmware) const {
    const auto found = recipes_.find(target.recipe_key);
    if (found == recipes_.end()) {
      throw std::runtime_error("firmware target recipe no longer exists");
    }
    const Recipe &recipe = found->second;
    if (firmware.size() != recipe.expected_size) {
      std::ostringstream message;
      message << "firmware must contain exactly 0x" << std::hex
              << recipe.expected_size << " bytes for " << recipe.component;
      throw std::invalid_argument(message.str());
    }
    Evaluator evaluator(recipe.scope);
    PopulateBindings(evaluator, recipe.bindings, recipe.source_variable,
                     &firmware);
    const Node &loop = recipe.api_write.children.at(recipe.loop_index);
    std::vector<UpdateAction> actions;
    TransferSettings settings;

    const std::size_t common_end =
        FirmwareSetupStart(recipe.api_write, recipe.first_loop_index);
    for (std::size_t index = 2; index < common_end; ++index) {
      AppendChunk(recipe.api_write.children[index], evaluator, settings,
                  actions);
    }
    const std::size_t component_start =
        FirmwareSetupStart(recipe.api_write, recipe.loop_index);
    for (std::size_t index = component_start; index < recipe.loop_index;
         ++index) {
      AppendChunk(recipe.api_write.children[index], evaluator, settings,
                  actions);
    }

    const std::int64_t loop_count = evaluator.Integer(loop.children[1]);
    for (std::int64_t iteration = 0; iteration < loop_count; ++iteration) {
      evaluator.Set("loopcount", iteration);
      for (std::size_t index = 2; index < loop.children.size(); ++index) {
        AppendChunk(loop.children[index], evaluator, settings, actions);
      }
    }

    std::size_t next_loop = recipe.last_loop_index + 1;
    for (std::size_t index = recipe.loop_index + 1;
         index <= recipe.last_loop_index; ++index) {
      if (Head(recipe.api_write.children[index]) == "chunk-loop") {
        next_loop = index;
        break;
      }
    }
    bool appended_source_tail = false;
    for (std::size_t index = recipe.loop_index + 1; index < next_loop;
         ++index) {
      const Node &node = recipe.api_write.children[index];
      if (ContainsAtom(node, recipe.source_variable)) {
        AppendChunk(node, evaluator, settings, actions);
        appended_source_tail = true;
      } else if (appended_source_tail && IsChunk(node) &&
                 node.children.size() >= 2 &&
                 node.children[1].kind == NodeKind::kAtom &&
                 node.children[1].text == "HIDSLEEP") {
        AppendChunk(node, evaluator, settings, actions);
      }
    }

    for (std::size_t index = recipe.last_loop_index + 1;
         index < recipe.api_write.children.size(); ++index) {
      AppendChunk(recipe.api_write.children[index], evaluator, settings,
                  actions);
    }

    AddResponseVerification(recipe, evaluator, settings, actions);
    if (recipe.api_finally) {
      AddFinallyReset(recipe, evaluator, actions);
    } else {
      actions.push_back({UpdateActionType::kReconnect, {}, {}, {}, {}});
    }
    if (actions.empty()) {
      throw std::runtime_error("descriptor produced no firmware actions");
    }
    return actions;
  }

  DeviceInfo FindReconnectedDevice(const FirmwareTarget &target) const {
    std::vector<DeviceInfo> candidates;
    for (const DeviceInfo &device : ListDevices()) {
      if (device.vendor_id != target.device.vendor_id ||
          device.usage_page != target.device.usage_page ||
          device.usage != target.device.usage ||
          std::find(target.reconnect_product_ids.begin(),
                    target.reconnect_product_ids.end(),
                    device.product_id) == target.reconnect_product_ids.end() ||
          (!target.device.serial.empty() &&
           device.serial != target.device.serial)) {
        continue;
      }
      candidates.push_back(device);
    }
    if (candidates.size() == 1) {
      return candidates.front();
    }
    for (const DeviceInfo &candidate : candidates) {
      if (candidate.path == target.device.path) {
        return candidate;
      }
    }
    throw std::runtime_error(candidates.empty()
                                 ? "target has not reappeared"
                                 : "reconnected target is ambiguous");
  }

private:
  void CompileVersionDocument(const Document &document, const Scope &global) {
    const std::string descriptor = document.path.stem().string();
    for (const Node &device : document.nodes) {
      if (Head(device) != "device" || device.children.size() < 2) {
        continue;
      }
      Scope scope = global;
      for (const Node &child : device.children) {
        AddDefinition(child, scope);
      }
      const auto device_id = EvaluateId(device.children[1], scope);
      const auto usage_page = DirectField(device, "usage-page", scope);
      const auto usage = DirectField(device, "usage", scope);
      if (!device_id || !usage_page || !usage) {
        continue;
      }

      std::vector<std::pair<std::string, const Node *>> version_apis;
      std::set<std::string> seen_apis;
      std::set<std::string> ambiguous_apis;
      for (const Node *api : FindReachableNodes(device, "api", scope)) {
        if (api->children.size() < 2 ||
            api->children[1].kind != NodeKind::kAtom ||
            !HasVersionToken(api->children[1].text)) {
          continue;
        }
        const std::string &name = api->children[1].text;
        if (!seen_apis.insert(name).second) {
          ambiguous_apis.insert(name);
        } else {
          version_apis.emplace_back(name, api);
        }
      }

      std::map<std::string, const Node *> structures;
      std::set<std::string> ambiguous_structures;
      for (const Node *structure :
           FindReachableNodes(device, "struct", scope)) {
        if (structure->children.size() < 2 ||
            structure->children[1].kind != NodeKind::kAtom) {
          continue;
        }
        const std::string &name = structure->children[1].text;
        if (!structures.emplace(name, structure).second) {
          ambiguous_structures.insert(name);
        }
      }
      for (const std::string &name : ambiguous_structures) {
        structures.erase(name);
      }

      std::vector<std::string> query_keys;
      for (const auto &[name, api] : version_apis) {
        if (ambiguous_apis.contains(name)) {
          continue;
        }
        const auto structure = structures.find(name);
        if (structure == structures.end()) {
          continue;
        }
        try {
          auto recipe = CompileVersionRecipe(*api, *structure->second, scope,
                                             VersionComponent(name));
          if (!recipe) {
            continue;
          }
          std::string key = descriptor;
          key += ':';
          key += std::to_string(*device_id);
          key += ':';
          key += name;
          version_recipes_[key] = std::move(*recipe);
          query_keys.push_back(std::move(key));
        } catch (const std::exception &) {
        }
      }
      if (!query_keys.empty()) {
        version_devices_.push_back({descriptor, *device_id, *usage_page, *usage,
                                    std::move(query_keys)});
      }
    }
  }

  void CompileDocument(const Document &document, const Scope &global) {
    const std::string descriptor = document.path.stem().string();
    for (const Node &device : document.nodes) {
      if (Head(device) != "device" || device.children.size() < 2) {
        continue;
      }
      Scope scope = global;
      for (const Node &child : device.children) {
        AddDefinition(child, scope);
      }
      const auto device_id = EvaluateId(device.children[1], scope);
      const auto usage_page = DirectField(device, "usage-page", scope);
      const auto usage = DirectField(device, "usage", scope);
      if (!device_id || !usage_page || !usage) {
        continue;
      }
      std::uint32_t main_id = *device_id;
      if (const auto function = scope.functions.find("get-main-product-id");
          function != scope.functions.end() &&
          function->second.parameters.empty() &&
          !function->second.body.empty()) {
        if (const auto value =
                EvaluateId(function->second.body.back(), scope)) {
          main_id = *value;
        }
      }
      const Node *api = FindFirmwareApi(device, scope);
      if (api == nullptr) {
        continue;
      }
      const Node *api_write = FindFirstNode(*api, "api-write");
      if (api_write == nullptr || api_write->children.size() < 3 ||
          api_write->children[1].kind != NodeKind::kAtom ||
          api_write->children[1].text != "HID") {
        continue;
      }
      const auto bindings = ApiBindings(*api);
      const auto sources = FirmwareSources(bindings, scope, engine_directory_);
      if (sources.empty()) {
        continue;
      }
      std::set<std::filesystem::path> explicit_files;
      for (const auto &[name, source] : sources) {
        (void)name;
        if (!source.primary) {
          explicit_files.insert(source.path.lexically_normal());
        }
      }
      std::vector<std::size_t> firmware_loops;
      for (std::size_t index = 2; index < api_write->children.size(); ++index) {
        if (Head(api_write->children[index]) != "chunk-loop") {
          continue;
        }
        if (!LoopSource(api_write->children[index], sources)) {
          firmware_loops.clear();
          break;
        }
        firmware_loops.push_back(index);
      }
      if (firmware_loops.empty()) {
        continue;
      }
      std::vector<std::string> recipe_keys;
      for (std::size_t index = 2; index < api_write->children.size(); ++index) {
        const Node &loop = api_write->children[index];
        if (Head(loop) != "chunk-loop") {
          continue;
        }
        const auto source_name = LoopSource(loop, sources);
        if (!source_name) {
          continue;
        }
        std::vector<Node> tail;
        for (std::size_t tail_index = index + 1;
             tail_index < api_write->children.size() &&
             Head(api_write->children[tail_index]) != "chunk-loop";
             ++tail_index) {
          if (ContainsAtom(api_write->children[tail_index], *source_name)) {
            tail.push_back(api_write->children[tail_index]);
          }
        }
        try {
          const std::size_t expected =
              ExpectedSize(loop, *source_name, scope, bindings, tail);
          std::filesystem::path stock = sources.at(*source_name).path;
          if (sources.at(*source_name).primary) {
            stock = FindPrimaryFirmware(engine_directory_, main_id, expected,
                                        explicit_files);
          }
          if (!std::filesystem::is_regular_file(stock) ||
              std::filesystem::file_size(stock) != expected) {
            continue;
          }
          const std::string &component = *source_name;
          const std::string version = SupportedVersion(scope, component);
          std::string key = descriptor;
          key += ':';
          key += std::to_string(*device_id);
          key += ':';
          key += component;
          Recipe recipe{
              component,    version,
              stock,        scope,
              *api_write,   std::nullopt,
              std::nullopt, bindings,
              *source_name, firmware_loops.front(),
              index,        firmware_loops.back(),
              expected,
          };
          if (const Node *finally = FindFirstNode(*api, "api-finally")) {
            recipe.api_finally = *finally;
            recipe.response_validator =
                FindResponseValidator(*finally, recipe.scope);
            const auto reads = FindNodes(*finally, "raw-read-from-device");
            if (reads.size() != 1 || !recipe.response_validator) {
              continue;
            }
          }
          recipes_[key] = std::move(recipe);
          recipe_keys.push_back(key);
        } catch (const std::exception &) {
        }
      }
      if (!recipe_keys.empty()) {
        devices_.push_back({descriptor,
                            *device_id,
                            main_id,
                            *usage_page,
                            *usage,
                            std::move(recipe_keys),
                            {}});
      }
    }
  }

  static void AddResponseVerification(const Recipe &recipe,
                                      Evaluator &evaluator,
                                      const TransferSettings &settings,
                                      std::vector<UpdateAction> &actions) {
    if (!recipe.api_finally) {
      return;
    }
    if (!recipe.response_validator) {
      throw std::runtime_error(
          "descriptor firmware response validator is unsupported");
    }
    const auto reads = FindNodes(*recipe.api_finally, "raw-read-from-device");
    if (reads.size() != 1) {
      throw std::runtime_error(
          "descriptor firmware response query is ambiguous");
    }
    const auto report = RawReport(*reads.front(), evaluator);
    if (!report) {
      throw std::runtime_error(
          "descriptor firmware response query cannot be evaluated");
    }
    const Scope scope = recipe.scope;
    const std::string validator = *recipe.response_validator;
    actions.push_back(
        {UpdateActionType::kVerifyResponse,
         *report,
         {},
         settings.query_timeout,
         [scope, validator](const Bytes &response) {
           if (!Evaluator(scope).Predicate(validator, response)) {
             throw std::runtime_error(
                 "descriptor firmware response verification failed");
           }
         }});
    if (settings.command_interval.count() > 0) {
      actions.push_back(
          {UpdateActionType::kSleep, {}, settings.command_interval, {}, {}});
    }
  }

  static void AddFinallyReset(const Recipe &recipe, Evaluator &evaluator,
                              std::vector<UpdateAction> &actions) {
    if (!recipe.api_finally) {
      return;
    }
    std::optional<Bytes> reset;
    for (const Node *call :
         FindNodes(*recipe.api_finally, "raw-write-to-device")) {
      try {
        if (const auto report = RawReport(*call, evaluator)) {
          reset = *report;
        }
      } catch (const std::exception &) {
      }
    }
    if (!reset) {
      throw std::runtime_error(
          "descriptor firmware reset command cannot be evaluated");
    }
    actions.push_back({UpdateActionType::kReset, *reset, {}, {}, {}});
  }

  std::filesystem::path engine_directory_;
  std::vector<DeviceDefinition> devices_;
  std::vector<VersionDeviceDefinition> version_devices_;
  std::unordered_map<std::string, Recipe> recipes_;
  std::unordered_map<std::string, VersionRecipe> version_recipes_;
};

Catalog::Catalog(const std::filesystem::path &program_directory)
    : impl_(std::make_unique<Impl>(program_directory)) {}

Catalog::Catalog(Catalog &&) noexcept = default;
Catalog &Catalog::operator=(Catalog &&) noexcept = default;
Catalog::~Catalog() = default;

FirmwareTarget Catalog::ResolveTarget(const std::string &device_address,
                                      const std::string &source_sha256) const {
  return impl_->ResolveTarget(device_address, source_sha256);
}

std::vector<FirmwareIdentity>
Catalog::IdentifyFirmware(const std::string &source_sha256) const {
  return impl_->IdentifyFirmware(source_sha256);
}

FirmwareVersionTarget
Catalog::ResolveVersionTarget(const std::string &device_address) const {
  return impl_->ResolveVersionTarget(device_address);
}

std::vector<FirmwareVersion>
Catalog::DecodeVersion(const FirmwareVersionQuery &query,
                       const std::vector<std::uint8_t> &response) const {
  return impl_->DecodeVersion(query, response);
}

std::vector<UpdateAction>
Catalog::BuildUpdate(const FirmwareTarget &target,
                     const std::vector<std::uint8_t> &firmware) const {
  return impl_->BuildUpdate(target, firmware);
}

DeviceInfo Catalog::FindReconnectedDevice(const FirmwareTarget &target) const {
  return impl_->FindReconnectedDevice(target);
}
