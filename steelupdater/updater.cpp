#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "catalog.h"
#include "container.h"
#include "device.h"
#include "updater.h"

namespace {

using namespace std::chrono_literals;

constexpr auto kDefaultQueryTimeout = 2s;
constexpr auto kReconnectPollDelay = 500ms;
constexpr auto kExternalPreflightRetryDelay = 500ms;
constexpr unsigned kExternalPreflightAttempts = 20;

struct HidObjectSettings {
  std::uint16_t object_id = 0;
  std::uint8_t route = 0;
  std::size_t report_size = 0;
  std::size_t block_size = 0;
  std::size_t stage_chunk_size = 0;
  std::size_t read_chunk_size = 0;
  std::chrono::milliseconds command_delay{};
  std::chrono::milliseconds erase_delay{};
  std::chrono::milliseconds load_delay{};
  std::chrono::milliseconds reset_delay{};
};

struct PreflightRegion {
  std::uint32_t offset = 0;
  std::size_t size = 0;
  std::vector<std::uint8_t> fills;
  std::vector<std::string> sha256;
};

struct PreflightState {
  std::string name;
  std::vector<PreflightRegion> regions;
};

struct ExternalPreflight {
  HidObjectSettings settings;
  std::vector<PreflightState> states;
};

struct AdditionalImage {
  std::filesystem::path path;
  std::vector<std::uint8_t> image;
  HidObjectSettings settings;
  ExternalPreflight preflight;
};

struct PatchInput {
  std::filesystem::path firmware_path;
  std::vector<std::uint8_t> firmware;
  std::vector<AdditionalImage> additional_images;
};

std::vector<std::uint8_t> ReadFile(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    throw std::runtime_error("could not open input file: " + path.string());
  }
  const std::streamsize size = input.tellg();
  if (size < 0) {
    throw std::runtime_error("could not determine input size: " +
                             path.string());
  }
  input.seekg(0);
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
  if (!bytes.empty() &&
      !input.read(reinterpret_cast<char *>(bytes.data()), size)) {
    throw std::runtime_error("could not read complete input: " + path.string());
  }
  return bytes;
}

bool IsSha256Hex(std::string_view value) {
  return value.size() == 64 &&
         std::all_of(value.begin(), value.end(), [](char character) {
           return (character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f');
         });
}

nlohmann::json ReadPatchReport(const std::filesystem::path &path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("could not open patch JSON: " + path.string());
  }
  nlohmann::json report;
  try {
    input >> report;
  } catch (const nlohmann::json::exception &) {
    throw std::runtime_error("patch JSON is invalid");
  }
  return report;
}

std::uint32_t ReadLe32(const std::vector<std::uint8_t> &bytes,
                       std::size_t offset) {
  if (offset + 4 > bytes.size()) {
    throw std::runtime_error("firmware vector table is truncated");
  }
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint32_t Crc32(const std::vector<std::uint8_t> &bytes) {
  std::uint32_t crc = 0xFFFFFFFFu;
  for (const std::uint8_t byte : bytes) {
    crc ^= byte;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^
            (0xEDB88320u &
             static_cast<std::uint32_t>(-static_cast<std::int32_t>(crc & 1u)));
    }
  }
  return ~crc;
}

void ValidateFirmware(const FirmwareTarget &target,
                      const std::vector<std::uint8_t> &firmware,
                      const std::vector<std::uint8_t> &stock) {
  if (firmware.size() != target.expected_size) {
    std::ostringstream message;
    message << "firmware must contain exactly 0x" << std::hex
            << target.expected_size << " bytes for " << target.component;
    throw std::invalid_argument(message.str());
  }
  if (stock.size() != target.expected_size) {
    throw std::runtime_error("GG stock firmware size no longer matches its "
                             "descriptor transaction");
  }
  if (Crc32(stock) == 0xFFFFFFFFu && Crc32(firmware) != 0xFFFFFFFFu) {
    throw std::invalid_argument(
        "firmware does not preserve the stock CRC32 residue");
  }
  if (stock.size() < 8) {
    return;
  }
  const std::uint32_t stock_stack = ReadLe32(stock, 0);
  const std::uint32_t stock_reset = ReadLe32(stock, 4);
  if ((stock_stack & 0xFF000000u) != 0x20000000u || (stock_reset & 1u) == 0u) {
    return;
  }
  const std::uint32_t stack = ReadLe32(firmware, 0);
  const std::uint32_t reset = ReadLe32(firmware, 4);
  if (stack != stock_stack || reset != stock_reset) {
    throw std::invalid_argument(
        "firmware vector table is incompatible with the GG stock image");
  }
}

std::uint64_t JsonUnsignedValue(const nlohmann::json &value,
                                std::string_view name) {
  if (value.is_number_unsigned()) {
    return value.get<std::uint64_t>();
  }
  if (value.is_number_integer()) {
    const std::int64_t integer = value.get<std::int64_t>();
    if (integer >= 0) {
      return static_cast<std::uint64_t>(integer);
    }
  }
  if (value.is_string()) {
    const std::string text = value.get<std::string>();
    std::size_t parsed = 0;
    try {
      const std::uint64_t result = std::stoull(text, &parsed, 0);
      if (parsed == text.size()) {
        return result;
      }
    } catch (const std::exception &) {
    }
  }
  throw std::runtime_error("patch report field " + std::string(name) +
                           " is not an unsigned integer");
}

std::uint64_t JsonUnsigned(const nlohmann::json &object,
                           std::string_view name) {
  const auto found = object.find(name);
  if (found == object.end()) {
    throw std::runtime_error("patch report is missing " + std::string(name));
  }
  return JsonUnsignedValue(*found, name);
}

std::vector<AdditionalImage>
LoadAdditionalImages(const std::filesystem::path &report_path,
                     const nlohmann::json &report,
                     const std::string &bundle_id) {
  const auto post_update = report.find("post_update");
  if (post_update == report.end() || !post_update->is_array()) {
    throw std::runtime_error("patch report post-update data is invalid");
  }

  std::vector<AdditionalImage> images;
  for (const nlohmann::json &specification : *post_update) {
    const std::string artifact = specification.value("artifact", std::string{});
    if (!specification.is_object() || artifact.empty() ||
        specification.value("protocol", std::string{}) !=
            "steelseries-hid-object-v1") {
      throw std::runtime_error("patch report image protocol is unsupported");
    }
    const std::filesystem::path name =
        specification.value("file", std::string{});
    if (name.empty() || name.is_absolute() || name != name.filename()) {
      throw std::runtime_error("patch report image path is not a filename");
    }
    const std::filesystem::path path = report_path.parent_path() / name;
    const auto container = ParseSteelpatchContainer(ReadFile(path));
    if (!container) {
      throw std::runtime_error("patch report image is not a steelpatcher "
                               "container: " +
                               path.string());
    }
    if (container->metadata.value("artifact", std::string{}) != artifact ||
        container->metadata.value("bundle_id", std::string{}) != bundle_id ||
        container->metadata.value("model", std::string{}) !=
            report.value("model", std::string{}) ||
        container->metadata.value("source_sha256", std::string{}) !=
            report.value("source_sha256", std::string{}) ||
        container->metadata.value("patches", nlohmann::json{}) !=
            report.value("patches", nlohmann::json{})) {
      throw std::runtime_error(
          "patch report image metadata does not match its bundle");
    }
    std::vector<std::uint8_t> image = container->payload;
    if (specification.value("sha256", std::string{}) != Sha256Hex(image)) {
      throw std::runtime_error("additional image SHA-256 differs from report");
    }

    const std::uint64_t object_id = JsonUnsigned(specification, "object_id");
    const std::uint64_t route = JsonUnsigned(specification, "route");
    const std::uint64_t report_size =
        JsonUnsigned(specification, "report_size");
    const std::uint64_t block_size = JsonUnsigned(specification, "block_size");
    const std::uint64_t stage_chunk_size =
        JsonUnsigned(specification, "stage_chunk_size");
    const std::uint64_t read_chunk_size =
        JsonUnsigned(specification, "read_chunk_size");
    const std::uint64_t command_delay =
        JsonUnsigned(specification, "command_delay_ms");
    const std::uint64_t erase_delay =
        JsonUnsigned(specification, "erase_delay_ms");
    const std::uint64_t load_delay =
        JsonUnsigned(specification, "load_delay_ms");
    const std::uint64_t reset_delay =
        JsonUnsigned(specification, "reset_delay_ms");
    if (object_id > std::numeric_limits<std::uint16_t>::max() || route > 0xFF ||
        report_size < 11 || report_size > kMaximumHidReportSize ||
        block_size == 0 ||
        block_size > std::numeric_limits<std::uint16_t>::max() ||
        stage_chunk_size == 0 || stage_chunk_size > report_size - 7 ||
        read_chunk_size == 0 || read_chunk_size >= report_size ||
        command_delay > 60'000 || erase_delay > 300'000 ||
        load_delay > 60'000 || reset_delay > 300'000 || image.empty() ||
        image.size() > std::numeric_limits<std::uint32_t>::max() ||
        image.size() % block_size != 0) {
      throw std::runtime_error("patch report image settings are invalid");
    }

    HidObjectSettings settings{static_cast<std::uint16_t>(object_id),
                               static_cast<std::uint8_t>(route),
                               static_cast<std::size_t>(report_size),
                               static_cast<std::size_t>(block_size),
                               static_cast<std::size_t>(stage_chunk_size),
                               static_cast<std::size_t>(read_chunk_size),
                               std::chrono::milliseconds(command_delay),
                               std::chrono::milliseconds(erase_delay),
                               std::chrono::milliseconds(load_delay),
                               std::chrono::milliseconds(reset_delay)};
    const auto preflight_specification = specification.find("preflight");
    if (preflight_specification == specification.end() ||
        !preflight_specification->is_object()) {
      throw std::runtime_error(
          "patch report external image has no destructive-write preflight");
    }
    const std::uint64_t preflight_object_id =
        JsonUnsigned(*preflight_specification, "object_id");
    const auto states = preflight_specification->find("states");
    if (preflight_object_id > std::numeric_limits<std::uint16_t>::max() ||
        states == preflight_specification->end() || !states->is_array() ||
        states->empty()) {
      throw std::runtime_error("patch report preflight settings are invalid");
    }
    ExternalPreflight preflight;
    preflight.settings = settings;
    preflight.settings.object_id =
        static_cast<std::uint16_t>(preflight_object_id);
    for (const nlohmann::json &state : *states) {
      if (!state.is_object()) {
        throw std::runtime_error("patch report preflight state is invalid");
      }
      const auto regions = state.find("regions");
      const std::string state_name = state.value("name", std::string{});
      if (state_name.empty() || regions == state.end() ||
          !regions->is_array() || regions->empty()) {
        throw std::runtime_error("patch report preflight state is invalid");
      }
      PreflightState parsed_state;
      parsed_state.name = state_name;
      for (const nlohmann::json &region : *regions) {
        if (!region.is_object()) {
          throw std::runtime_error("patch report preflight region is invalid");
        }
        const std::uint64_t offset = JsonUnsigned(region, "offset");
        const std::uint64_t size = JsonUnsigned(region, "size");
        const auto fills = region.find("fill");
        const auto hashes = region.find("sha256");
        if (offset > std::numeric_limits<std::uint32_t>::max() || size == 0 ||
            size > std::numeric_limits<std::uint32_t>::max() ||
            offset + size > (std::uint64_t{1} << 32) ||
            (fills != region.end()) == (hashes != region.end())) {
          throw std::runtime_error("patch report preflight region is invalid");
        }
        PreflightRegion parsed_region;
        parsed_region.offset = static_cast<std::uint32_t>(offset);
        parsed_region.size = static_cast<std::size_t>(size);
        if (fills != region.end()) {
          if (!fills->is_array() || fills->empty()) {
            throw std::runtime_error(
                "patch report preflight fill list is invalid");
          }
          for (const nlohmann::json &fill : *fills) {
            const std::uint64_t value = JsonUnsignedValue(fill, "fill");
            if (value > 0xFF) {
              throw std::runtime_error(
                  "patch report preflight fill is not one byte");
            }
            parsed_region.fills.push_back(static_cast<std::uint8_t>(value));
          }
        } else {
          if (!hashes->is_array() || hashes->empty()) {
            throw std::runtime_error(
                "patch report preflight SHA-256 list is invalid");
          }
          for (const nlohmann::json &hash : *hashes) {
            if (!hash.is_string()) {
              throw std::runtime_error(
                  "patch report preflight SHA-256 is not a string");
            }
            const std::string value = hash.get<std::string>();
            if (!IsSha256Hex(value)) {
              throw std::runtime_error(
                  "patch report preflight SHA-256 is invalid");
            }
            parsed_region.sha256.push_back(value);
          }
        }
        parsed_state.regions.push_back(std::move(parsed_region));
      }
      preflight.states.push_back(std::move(parsed_state));
    }
    images.push_back({path, std::move(image), settings, std::move(preflight)});
  }
  return images;
}

PatchInput LoadPatchInput(const std::filesystem::path &report_path,
                          const nlohmann::json &report,
                          const std::vector<std::uint8_t> &stock) {
  const std::string bundle_id = report.value("bundle_id", std::string{});
  const std::filesystem::path firmware_name =
      report.value("firmware", std::string{});
  const auto post_update = report.find("post_update");
  const auto patches = report.find("patches");
  if (!report.is_object() || report.value("schema_version", 0) != 1 ||
      bundle_id.empty() || report.value("model", std::string{}).empty() ||
      report.value("source_sha256", std::string{}) != Sha256Hex(stock) ||
      firmware_name.empty() || firmware_name.is_absolute() ||
      firmware_name != firmware_name.filename() ||
      post_update == report.end() || !post_update->is_array() ||
      patches == report.end() || !patches->is_array() || patches->empty()) {
    throw std::runtime_error(
        "patch JSON does not match the selected GG firmware target");
  }

  nlohmann::json bundle_description = {
      {"schema_version", 1},
      {"model", report["model"]},
      {"patches", *patches},
      {"source_sha256", report["source_sha256"]},
      {"firmware",
       {{"file", firmware_name.string()},
        {"sha256", report.value("firmware_sha256", std::string{})}}},
      {"post_update", *post_update},
  };
  const std::string serialized_bundle = bundle_description.dump(-1, ' ', true);
  const std::vector<std::uint8_t> bundle_bytes(serialized_bundle.begin(),
                                               serialized_bundle.end());
  if (bundle_id != Sha256Hex(bundle_bytes)) {
    throw std::runtime_error("patch JSON bundle digest is invalid");
  }

  const std::filesystem::path firmware_path =
      report_path.parent_path() / firmware_name;
  auto container = ParseSteelpatchContainer(ReadFile(firmware_path));
  if (!container) {
    throw std::runtime_error(
        "patch JSON firmware is not a steelpatcher container");
  }
  if (container->metadata.value("artifact", std::string{}) != "firmware" ||
      container->metadata.value("bundle_id", std::string{}) != bundle_id ||
      container->metadata.value("model", std::string{}) !=
          report.value("model", std::string{}) ||
      container->metadata.value("source_sha256", std::string{}) !=
          report.value("source_sha256", std::string{}) ||
      container->metadata.value("patches", nlohmann::json{}) != *patches ||
      report.value("firmware_sha256", std::string{}) !=
          Sha256Hex(container->payload)) {
    throw std::runtime_error(
        "patch JSON firmware metadata does not match its bundle");
  }
  std::vector<AdditionalImage> additional_images =
      LoadAdditionalImages(report_path, report, bundle_id);
  return {firmware_path, std::move(container->payload),
          std::move(additional_images)};
}

void WriteLe16(std::uint8_t *bytes, std::uint16_t value) {
  bytes[0] = static_cast<std::uint8_t>(value);
  bytes[1] = static_cast<std::uint8_t>(value >> 8);
}

void WriteLe32(std::uint8_t *bytes, std::uint32_t value) {
  bytes[0] = static_cast<std::uint8_t>(value);
  bytes[1] = static_cast<std::uint8_t>(value >> 8);
  bytes[2] = static_cast<std::uint8_t>(value >> 16);
  bytes[3] = static_cast<std::uint8_t>(value >> 24);
}

std::vector<std::uint8_t> Query(Device &device,
                                const std::vector<std::uint8_t> &report,
                                std::chrono::milliseconds timeout) {
  device.FlushInput();
  device.Write(report);
  auto response =
      device.Read(timeout.count() > 0 ? timeout : kDefaultQueryTimeout);
  if (!response) {
    throw std::runtime_error("firmware command timed out");
  }
  device.FlushInput();
  if (response->size() == report.size() && !response->empty() &&
      response->front() == report.front()) {
    response->erase(response->begin());
  }
  return *response;
}

class HidObjectProtocol {
public:
  HidObjectProtocol(Device &device, const HidObjectSettings &settings)
      : device_(device), settings_(settings) {
    for (const std::uint8_t opcode :
         {std::uint8_t{0x01}, std::uint8_t{0x03}, std::uint8_t{0x05},
          std::uint8_t{0x08}, std::uint8_t{0x83}, std::uint8_t{0x85}}) {
      if ((opcode & settings_.route) != 0) {
        throw std::runtime_error("image route overlaps a protocol command bit");
      }
    }
  }

  std::vector<std::uint8_t> Read(std::uint32_t object_offset,
                                 std::size_t size) {
    if (size == 0 || static_cast<std::uint64_t>(object_offset) + size >
                         (std::uint64_t{1} << 32)) {
      throw std::runtime_error("object read range is invalid");
    }
    std::vector<std::uint8_t> readback;
    readback.reserve(size);
    while (readback.size() < size) {
      const std::size_t block_size =
          std::min(settings_.block_size, size - readback.size());
      std::vector<std::uint8_t> load = Report(0x85);
      WriteLe16(load.data() + 3, settings_.object_id);
      WriteLe32(load.data() + 5,
                object_offset + static_cast<std::uint32_t>(readback.size()));
      WriteLe16(load.data() + 9, static_cast<std::uint16_t>(block_size));
      Write(load);
      std::this_thread::sleep_for(settings_.load_delay);
      for (std::size_t offset = 0; offset < block_size;
           offset += settings_.read_chunk_size) {
        const std::size_t chunk_size =
            std::min(settings_.read_chunk_size, block_size - offset);
        std::vector<std::uint8_t> read = Report(0x83);
        WriteLe16(read.data() + 3, static_cast<std::uint16_t>(offset));
        WriteLe16(read.data() + 5, static_cast<std::uint16_t>(chunk_size));
        const std::vector<std::uint8_t> response =
            Query(device_, read, kDefaultQueryTimeout);
        if (response.size() < chunk_size) {
          throw std::runtime_error("image readback response is truncated");
        }
        readback.insert(readback.end(), response.begin(),
                        response.begin() +
                            static_cast<std::ptrdiff_t>(chunk_size));
      }
    }
    return readback;
  }

  void Install(const std::vector<std::uint8_t> &image) {
    std::vector<std::uint8_t> erase = Report(0x08);
    WriteLe16(erase.data() + 3, settings_.object_id);
    Write(erase);
    std::this_thread::sleep_for(settings_.erase_delay);

    for (std::size_t block_offset = 0; block_offset < image.size();
         block_offset += settings_.block_size) {
      const auto block =
          image.begin() + static_cast<std::ptrdiff_t>(block_offset);
      if (std::all_of(block,
                      block + static_cast<std::ptrdiff_t>(settings_.block_size),
                      [](std::uint8_t byte) { return byte == 0xFF; })) {
        continue;
      }
      for (std::size_t offset = 0; offset < settings_.block_size;
           offset += settings_.stage_chunk_size) {
        const std::size_t size =
            std::min(settings_.stage_chunk_size, settings_.block_size - offset);
        std::vector<std::uint8_t> stage = Report(0x03);
        WriteLe16(stage.data() + 3, static_cast<std::uint16_t>(offset));
        WriteLe16(stage.data() + 5, static_cast<std::uint16_t>(size));
        std::copy_n(image.begin() +
                        static_cast<std::ptrdiff_t>(block_offset + offset),
                    size, stage.begin() + 7);
        Write(stage);
      }
      std::vector<std::uint8_t> commit = Report(0x05);
      WriteLe16(commit.data() + 3, settings_.object_id);
      WriteLe32(commit.data() + 5, static_cast<std::uint32_t>(block_offset));
      WriteLe16(commit.data() + 9,
                static_cast<std::uint16_t>(settings_.block_size));
      Write(commit);
    }

    if (Read(0, image.size()) != image) {
      throw std::runtime_error("image readback differs from input");
    }

    try {
      Write(Report(0x01));
    } catch (const std::exception &) {
    }
    std::this_thread::sleep_for(settings_.reset_delay);
  }

private:
  std::vector<std::uint8_t> Report(std::uint8_t opcode) const {
    std::vector<std::uint8_t> report(settings_.report_size);
    report[1] = static_cast<std::uint8_t>(opcode | settings_.route);
    return report;
  }

  void Write(const std::vector<std::uint8_t> &report) {
    device_.Write(report);
    std::this_thread::sleep_for(settings_.command_delay);
  }

  Device &device_;
  HidObjectSettings settings_;
};

void RequireExternalPreflight(Device &device,
                              const ExternalPreflight &preflight) {
  using RegionKey = std::pair<std::uint32_t, std::size_t>;

  HidObjectProtocol protocol(device, preflight.settings);
  std::map<RegionKey, std::vector<std::uint8_t>> observed;
  for (const PreflightState &state : preflight.states) {
    for (const PreflightRegion &region : state.regions) {
      const RegionKey key{region.offset, region.size};
      if (observed.find(key) == observed.end()) {
        for (unsigned attempt = 0; attempt < kExternalPreflightAttempts;
             ++attempt) {
          try {
            observed.emplace(key, protocol.Read(region.offset, region.size));
            break;
          } catch (const std::exception &) {
            if (attempt + 1 == kExternalPreflightAttempts) {
              throw;
            }
            std::this_thread::sleep_for(kExternalPreflightRetryDelay);
          }
        }
      }
    }
  }
  for (const auto &[region, bytes] : observed) {
    std::cout << "external Flash preflight offset 0x" << std::hex
              << region.first << std::dec << ", size " << region.second
              << ", SHA-256 " << Sha256Hex(bytes) << '\n';
  }
  for (const PreflightState &state : preflight.states) {
    const bool matches = std::all_of(
        state.regions.begin(), state.regions.end(),
        [&observed](const PreflightRegion &region) {
          const std::vector<std::uint8_t> &bytes =
              observed.at({region.offset, region.size});
          if (!region.fills.empty()) {
            return std::any_of(region.fills.begin(), region.fills.end(),
                               [&bytes](std::uint8_t fill) {
                                 return std::all_of(bytes.begin(), bytes.end(),
                                                    [fill](std::uint8_t byte) {
                                                      return byte == fill;
                                                    });
                               });
          }
          const std::string hash = Sha256Hex(bytes);
          return std::find(region.sha256.begin(), region.sha256.end(), hash) !=
                 region.sha256.end();
        });
    if (matches) {
      std::cout << "external Flash preflight matched state " << state.name
                << '\n';
      return;
    }
  }
  throw std::runtime_error(
      "external Flash contains unknown data; refusing external-image write");
}

DeviceInfo WaitForTarget(const Catalog &catalog, const FirmwareTarget &target) {
  std::string last_error = "target has not reappeared";
  std::optional<std::string> previous_path;
  for (unsigned attempt = 0; attempt < 20; ++attempt) {
    std::this_thread::sleep_for(kReconnectPollDelay);
    try {
      DeviceInfo device = catalog.FindReconnectedDevice(target);
      if (device.product_id != target.device.product_id) {
        last_error = "target remains in its bootloader or recovery mode";
        previous_path.reset();
        continue;
      }
      if (previous_path == device.path) {
        return device;
      }
      previous_path = device.path;
    } catch (const std::exception &error) {
      last_error = error.what();
      previous_path.reset();
    }
  }
  throw std::runtime_error("device did not reconnect stably: " + last_error);
}

void PerformUpdate(const Catalog &catalog, const FirmwareTarget &target,
                   const std::filesystem::path &firmware_path,
                   const std::vector<std::uint8_t> &firmware,
                   const std::vector<AdditionalImage> &additional_images) {
  const std::vector<UpdateAction> actions =
      catalog.BuildUpdate(target, firmware);
  const std::size_t command_count = static_cast<std::size_t>(std::count_if(
      actions.begin(), actions.end(), [](const UpdateAction &action) {
        return action.type != UpdateActionType::kSleep &&
               action.type != UpdateActionType::kReconnect;
      }));
  std::cout << "updating " << target.label << " with " << firmware_path << '\n';
  bool reconnect_required = false;
  {
    std::size_t completed = 0;
    unsigned reported_percent = 0;
    Device device(target.device);
    for (const UpdateAction &action : actions) {
      if (action.type == UpdateActionType::kSleep) {
        std::this_thread::sleep_for(action.delay);
        continue;
      }
      if (action.type == UpdateActionType::kReconnect) {
        reconnect_required = true;
        continue;
      }
      if (action.type == UpdateActionType::kWrite) {
        device.Write(action.report);
      } else if (action.type == UpdateActionType::kWriteNoFail) {
        try {
          device.Write(action.report);
        } catch (const std::exception &) {
        }
      } else if (action.type == UpdateActionType::kQuery) {
        (void)Query(device, action.report, action.timeout);
      } else if (action.type == UpdateActionType::kVerifyResponse) {
        if (!action.verify_response) {
          throw std::runtime_error(
              "descriptor response action has no verifier");
        }
        action.verify_response(Query(device, action.report, action.timeout));
      } else if (action.type == UpdateActionType::kReset) {
        reconnect_required = true;
        try {
          device.Write(action.report);
        } catch (const std::exception &) {
        }
      }
      ++completed;
      const unsigned percent =
          command_count == 0
              ? 100
              : static_cast<unsigned>(completed * 100 / command_count);
      if (percent >= reported_percent + 5 || percent == 100) {
        reported_percent = percent;
        std::cout << '\r' << std::setw(3) << percent << "%" << std::flush;
      }
    }
  }
  std::cout << '\n';
  DeviceInfo active_device = target.device;
  if (reconnect_required) {
    active_device = WaitForTarget(catalog, target);
  }
  if (!additional_images.empty()) {
    Device device(active_device);
    for (const AdditionalImage &image : additional_images) {
      RequireExternalPreflight(device, image.preflight);
    }
  }
  for (const AdditionalImage &additional : additional_images) {
    std::cout << "installing additional image " << additional.path << '\n';
    {
      Device device(active_device);
      HidObjectProtocol(device, additional.settings).Install(additional.image);
    }
    active_device = WaitForTarget(catalog, target);
  }
  {
    Device device(active_device);
    device.FlushInput();
  }
  std::cout << "firmware update complete\n";
}

} // namespace

void CheckDeviceVersion(const Catalog &catalog,
                        const std::string &device_address) {
  const FirmwareVersionTarget target =
      catalog.ResolveVersionTarget(device_address);
  Device device(target.device);
  std::vector<FirmwareVersion> versions;
  for (const FirmwareVersionQuery &query : target.queries) {
    device.FlushInput();
    device.Write(query.report);
    const auto response = device.Read(query.timeout);
    if (!response) {
      throw std::runtime_error("firmware version query timed out");
    }
    std::vector<FirmwareVersion> decoded =
        catalog.DecodeVersion(query, *response);
    versions.insert(versions.end(), std::make_move_iterator(decoded.begin()),
                    std::make_move_iterator(decoded.end()));
    if (query.command_delay.count() > 0) {
      std::this_thread::sleep_for(query.command_delay);
    }
  }
  if (versions.empty()) {
    throw std::runtime_error("device returned no firmware versions");
  }
  std::cout << target.product << '\n';
  for (const FirmwareVersion &version : versions) {
    std::cout << "  " << version.component << ": " << version.version << '\n';
  }
}

void CheckFirmwareVersion(const Catalog &catalog,
                          const std::filesystem::path &firmware_path) {
  const std::vector<std::uint8_t> file = ReadFile(firmware_path);
  const std::optional<SteelpatchContainer> container =
      ParseSteelpatchContainer(file);
  const std::vector<std::uint8_t> &payload =
      container ? container->payload : file;
  const std::string source_sha256 =
      container ? container->metadata.value("source_sha256", std::string{})
                : Sha256Hex(file);
  const std::vector<FirmwareIdentity> identities =
      catalog.IdentifyFirmware(source_sha256);

  std::cout << firmware_path.string() << '\n';
  if (identities.size() == 1) {
    std::cout << "  model: " << identities.front().model << '\n'
              << "  component: " << identities.front().component << '\n'
              << "  version: " << identities.front().version << '\n';
  } else if (identities.empty()) {
    std::cout << "  model: unknown\n"
              << "  component: unknown\n"
              << "  version: unknown\n";
  } else {
    std::cout << "  matches:\n";
    for (const FirmwareIdentity &identity : identities) {
      std::cout << "    " << identity.model << " / " << identity.component
                << " / " << identity.version << '\n';
    }
  }
  std::cout << "  size: " << file.size() << " bytes\n"
            << "  SHA-256: " << Sha256Hex(file) << '\n';
  if (container) {
    std::cout << "  payload size: " << payload.size() << " bytes\n"
              << "  payload SHA-256: " << Sha256Hex(payload) << '\n';
  }
  std::cout << "  verified: " << (identities.empty() ? "no" : "yes") << '\n';
}

void UpdateFirmware(const Catalog &catalog, const std::string &device_address,
                    const std::filesystem::path &firmware_path) {
  const std::vector<std::uint8_t> firmware = ReadFile(firmware_path);
  if (ParseSteelpatchContainer(firmware)) {
    throw std::invalid_argument(
        "input is a steelpatcher container; use --json with its patch JSON");
  }
  const FirmwareTarget target =
      catalog.ResolveTarget(device_address, Sha256Hex(firmware));
  const std::vector<std::uint8_t> stock = ReadFile(target.stock_firmware);
  ValidateFirmware(target, firmware, stock);
  PerformUpdate(catalog, target, firmware_path, firmware, {});
}

void UpdatePatchedFirmware(const Catalog &catalog,
                           const std::string &device_address,
                           const std::filesystem::path &report_path) {
  const nlohmann::json report = ReadPatchReport(report_path);
  if (!report.is_object() || report.value("schema_version", 0) != 1) {
    throw std::runtime_error("patch JSON source identity is invalid");
  }
  const std::string source_sha256 =
      report.value("source_sha256", std::string{});
  if (!IsSha256Hex(source_sha256)) {
    throw std::runtime_error("patch JSON source identity is invalid");
  }
  const FirmwareTarget target =
      catalog.ResolveTarget(device_address, source_sha256);
  const std::vector<std::uint8_t> stock = ReadFile(target.stock_firmware);
  PatchInput input = LoadPatchInput(report_path, report, stock);
  ValidateFirmware(target, input.firmware, stock);
  PerformUpdate(catalog, target, input.firmware_path, input.firmware,
                input.additional_images);
}
