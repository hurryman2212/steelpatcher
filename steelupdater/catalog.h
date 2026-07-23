#ifndef STEELPATCHER_STEELUPDATER_CATALOG_H_
#define STEELPATCHER_STEELUPDATER_CATALOG_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "device.h"

enum class UpdateActionType {
  kWrite,
  kWriteNoFail,
  kQuery,
  kVerifyResponse,
  kReset,
  kReconnect,
  kSleep,
};

struct UpdateAction {
  UpdateActionType type = UpdateActionType::kWrite;
  std::vector<std::uint8_t> report;
  std::chrono::milliseconds delay{};
  std::chrono::milliseconds timeout{};
  std::function<void(const std::vector<std::uint8_t> &)> verify_response;
};

struct FirmwareTarget {
  std::string device_address;
  std::string component;
  std::string label;
  DeviceInfo device;
  std::filesystem::path stock_firmware;
  std::size_t expected_size = 0;
  std::vector<std::uint16_t> reconnect_product_ids;
  std::string recipe_key;
};

struct FirmwareIdentity {
  std::string model;
  std::string component;
  std::string version;
  std::filesystem::path stock_firmware;
};

struct FirmwareVersion {
  std::string component;
  std::string version;
};

struct FirmwareVersionQuery {
  std::string query_key;
  std::vector<std::uint8_t> report;
  std::chrono::milliseconds timeout{};
  std::chrono::milliseconds command_delay{};
};

struct FirmwareVersionTarget {
  std::string product;
  DeviceInfo device;
  std::vector<FirmwareVersionQuery> queries;
};

class Catalog {
public:
  explicit Catalog(const std::filesystem::path &program_directory);
  Catalog(const Catalog &) = delete;
  Catalog &operator=(const Catalog &) = delete;
  Catalog(Catalog &&) noexcept;
  Catalog &operator=(Catalog &&) noexcept;
  ~Catalog();

  FirmwareTarget ResolveTarget(const std::string &device_address,
                               const std::string &source_sha256) const;
  std::vector<FirmwareIdentity>
  IdentifyFirmware(const std::string &source_sha256) const;
  FirmwareVersionTarget
  ResolveVersionTarget(const std::string &device_address) const;
  std::vector<FirmwareVersion>
  DecodeVersion(const FirmwareVersionQuery &query,
                const std::vector<std::uint8_t> &response) const;
  std::vector<UpdateAction>
  BuildUpdate(const FirmwareTarget &target,
              const std::vector<std::uint8_t> &firmware) const;
  DeviceInfo FindReconnectedDevice(const FirmwareTarget &target) const;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

#endif
