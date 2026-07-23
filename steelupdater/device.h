#ifndef STEELPATCHER_STEELUPDATER_DEVICE_H_
#define STEELPATCHER_STEELUPDATER_DEVICE_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct hid_device_;

inline constexpr std::size_t kMaximumHidReportSize = 4096;

struct DeviceInfo {
  std::string path;
  std::string serial;
  std::string product;
  std::uint16_t vendor_id = 0;
  std::uint16_t product_id = 0;
  std::uint16_t usage_page = 0;
  std::uint16_t usage = 0;
};

void InitializeHid();
void ShutdownHid();
std::vector<DeviceInfo> ListDevices();
std::vector<DeviceInfo> ListFirmwareDevices();
bool IsSteelSeriesFirmwareInterface(const DeviceInfo &device);
std::string FormatDeviceAddress(const DeviceInfo &device, std::size_t index);

class Device {
public:
  explicit Device(const DeviceInfo &information);
  Device(const Device &) = delete;
  Device &operator=(const Device &) = delete;
  ~Device();

  void FlushInput();
  void Write(const std::vector<std::uint8_t> &report);
  std::optional<std::vector<std::uint8_t>>
  Read(std::chrono::milliseconds timeout);

private:
  hid_device_ *handle_ = nullptr;
};

#endif
