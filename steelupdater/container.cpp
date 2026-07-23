#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include "container.h"

namespace {

constexpr std::array<std::uint8_t, 16> kSteelpatchMagic = {
    0x89, 0x53, 0x50, 0x46, 0x57, 0x0D, 0x0A, 0x1A,
    0x0A, 0x7D, 0x19, 0x91, 0xDE, 0x01, 0x5A, 0xBC};
constexpr std::size_t kSteelpatchFooterSize = 128;
constexpr std::size_t kPayloadDigestOffset = 40;
constexpr std::size_t kMetadataDigestOffset = 72;
constexpr std::size_t kReservedOffset = 104;

std::uint32_t ReadLe32(const std::uint8_t *bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8) |
         (static_cast<std::uint32_t>(bytes[2]) << 16) |
         (static_cast<std::uint32_t>(bytes[3]) << 24);
}

std::uint64_t ReadLe64(const std::uint8_t *bytes) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
  }
  return value;
}

std::array<std::uint8_t, 32> Sha256(const std::uint8_t *bytes,
                                    std::size_t size) {
  std::array<std::uint8_t, 32> digest{};
  unsigned digest_size = 0;
  if (EVP_Digest(bytes, size, digest.data(), &digest_size, EVP_sha256(),
                 nullptr) != 1 ||
      digest_size != digest.size()) {
    throw std::runtime_error("could not calculate SHA-256");
  }
  return digest;
}

std::string Hex(const std::array<std::uint8_t, 32> &bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    result[index * 2] = digits[bytes[index] >> 4];
    result[index * 2 + 1] = digits[bytes[index] & 0x0F];
  }
  return result;
}

bool IsSha256(const nlohmann::json &value) {
  if (!value.is_string()) {
    return false;
  }
  const std::string text = value.get<std::string>();
  return text.size() == 64 &&
         std::all_of(text.begin(), text.end(), [](char character) {
           return (character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f');
         });
}

} // namespace

std::string Sha256Hex(const std::vector<std::uint8_t> &bytes) {
  return Hex(Sha256(bytes.data(), bytes.size()));
}

std::optional<SteelpatchContainer>
ParseSteelpatchContainer(const std::vector<std::uint8_t> &bytes) {
  const auto first_magic =
      std::search(bytes.begin(), bytes.end(), kSteelpatchMagic.begin(),
                  kSteelpatchMagic.end());
  if (bytes.size() < kSteelpatchFooterSize) {
    if (first_magic != bytes.end()) {
      throw std::runtime_error("steelpatcher container footer is truncated");
    }
    return std::nullopt;
  }

  const std::size_t footer_offset = bytes.size() - kSteelpatchFooterSize;
  const auto expected_magic =
      bytes.begin() + static_cast<std::ptrdiff_t>(footer_offset);
  if (!std::equal(kSteelpatchMagic.begin(), kSteelpatchMagic.end(),
                  expected_magic)) {
    if (first_magic != bytes.end()) {
      throw std::runtime_error(
          "steelpatcher container marker is not in a valid footer");
    }
    return std::nullopt;
  }

  const std::uint8_t *footer = bytes.data() + footer_offset;
  if (ReadLe32(footer + 16) != 1 ||
      ReadLe32(footer + 20) != kSteelpatchFooterSize) {
    throw std::runtime_error("steelpatcher container version is unsupported");
  }
  if (!std::all_of(footer + kReservedOffset, footer + kSteelpatchFooterSize,
                   [](std::uint8_t byte) { return byte == 0; })) {
    throw std::runtime_error("steelpatcher container reserved data is invalid");
  }

  const std::uint64_t payload_size = ReadLe64(footer + 24);
  const std::uint64_t metadata_size = ReadLe64(footer + 32);
  if (payload_size > std::numeric_limits<std::size_t>::max() ||
      metadata_size > std::numeric_limits<std::size_t>::max() ||
      payload_size > footer_offset ||
      metadata_size != footer_offset - payload_size) {
    throw std::runtime_error("steelpatcher container lengths are invalid");
  }
  const std::size_t parsed_payload_size =
      static_cast<std::size_t>(payload_size);
  const std::size_t parsed_metadata_size =
      static_cast<std::size_t>(metadata_size);
  const std::uint8_t *metadata = bytes.data() + parsed_payload_size;
  const auto payload_digest = Sha256(bytes.data(), parsed_payload_size);
  const auto metadata_digest = Sha256(metadata, parsed_metadata_size);
  if (!std::equal(payload_digest.begin(), payload_digest.end(),
                  footer + kPayloadDigestOffset) ||
      !std::equal(metadata_digest.begin(), metadata_digest.end(),
                  footer + kMetadataDigestOffset)) {
    throw std::runtime_error("steelpatcher container SHA-256 is invalid");
  }

  nlohmann::json parsed_metadata;
  try {
    parsed_metadata = nlohmann::json::parse(
        metadata, metadata + parsed_metadata_size, nullptr, true, false);
  } catch (const nlohmann::json::exception &) {
    throw std::runtime_error("steelpatcher container metadata is invalid JSON");
  }
  const auto payload_size_field = parsed_metadata.find("payload_size");
  const auto payload_hash_field = parsed_metadata.find("payload_sha256");
  const auto bundle_field = parsed_metadata.find("bundle_id");
  const auto patches_field = parsed_metadata.find("patches");
  if (!parsed_metadata.is_object() ||
      parsed_metadata.value("schema_version", 0) != 1 ||
      parsed_metadata.value("format", std::string{}) != "steelpatcher-bin" ||
      parsed_metadata.value("artifact", std::string{}).empty() ||
      parsed_metadata.value("model", std::string{}).empty() ||
      payload_size_field == parsed_metadata.end() ||
      !payload_size_field->is_number_unsigned() ||
      payload_size_field->get<std::uint64_t>() != payload_size ||
      payload_hash_field == parsed_metadata.end() ||
      !IsSha256(*payload_hash_field) ||
      payload_hash_field->get<std::string>() != Hex(payload_digest) ||
      bundle_field == parsed_metadata.end() || !IsSha256(*bundle_field) ||
      parsed_metadata.find("source_sha256") == parsed_metadata.end() ||
      !IsSha256(parsed_metadata["source_sha256"]) ||
      patches_field == parsed_metadata.end() || !patches_field->is_array() ||
      patches_field->empty() ||
      !std::all_of(patches_field->begin(), patches_field->end(),
                   [](const nlohmann::json &patch) {
                     return patch.is_string() &&
                            !patch.get<std::string>().empty();
                   })) {
    throw std::runtime_error("steelpatcher container metadata is inconsistent");
  }

  return SteelpatchContainer{
      std::vector<std::uint8_t>(
          bytes.begin(),
          bytes.begin() + static_cast<std::ptrdiff_t>(parsed_payload_size)),
      std::move(parsed_metadata)};
}
