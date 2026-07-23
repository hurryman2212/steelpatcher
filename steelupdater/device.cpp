#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <hidapi.h>

#include "device.h"

namespace {

constexpr std::uint16_t kSteelSeriesVendorId = 0x1038;
constexpr std::uint16_t kFirmwareUsagePage = 0xFFC0;
constexpr std::uint16_t kFirmwareUsage = 0x0001;

std::string Narrow(const wchar_t *value) {
  if (value == nullptr) {
    return {};
  }
  std::ostringstream output;
  for (const wchar_t character : std::wstring(value)) {
    output << (character <= 0x7F ? static_cast<char>(character) : '?');
  }
  return output.str();
}

std::string HidError(hid_device *device) {
  const std::string message = Narrow(hid_error(device));
  return message.empty() ? "unknown HID error" : message;
}

} // namespace

void InitializeHid() {
  if (hid_init() != 0) {
    throw std::runtime_error("could not initialize HIDAPI");
  }
}

void ShutdownHid() { hid_exit(); }

std::vector<DeviceInfo> ListDevices() {
  std::vector<DeviceInfo> devices;
  hid_device_info *list = hid_enumerate(kSteelSeriesVendorId, 0);
  for (hid_device_info *item = list; item != nullptr; item = item->next) {
    devices.push_back({item->path, Narrow(item->serial_number),
                       Narrow(item->product_string), item->vendor_id,
                       item->product_id, item->usage_page, item->usage});
  }
  hid_free_enumeration(list);
  return devices;
}

std::vector<DeviceInfo> ListFirmwareDevices() {
  std::vector<DeviceInfo> devices = ListDevices();
  std::erase_if(devices, [](const DeviceInfo &device) {
    return !IsSteelSeriesFirmwareInterface(device);
  });
  std::sort(devices.begin(), devices.end(),
            [](const DeviceInfo &left, const DeviceInfo &right) {
              return std::tie(left.vendor_id, left.product_id, left.serial,
                              left.path) < std::tie(right.vendor_id,
                                                    right.product_id,
                                                    right.serial, right.path);
            });
  return devices;
}

bool IsSteelSeriesFirmwareInterface(const DeviceInfo &device) {
  return device.vendor_id == kSteelSeriesVendorId &&
         device.usage_page == kFirmwareUsagePage &&
         device.usage == kFirmwareUsage;
}

std::string FormatDeviceAddress(const DeviceInfo &device, std::size_t index) {
  std::ostringstream address;
  address << std::hex << std::setfill('0') << std::setw(4) << device.vendor_id
          << ':' << std::setw(4) << device.product_id << ':' << std::dec
          << index;
  return address.str();
}

Device::Device(const DeviceInfo &information) {
  handle_ = hid_open_path(information.path.c_str());
  if (handle_ == nullptr) {
    throw std::runtime_error("could not open HID target");
  }
  if (hid_set_nonblocking(handle_, 0) != 0) {
    const std::string message = HidError(handle_);
    hid_close(handle_);
    handle_ = nullptr;
    throw std::runtime_error("could not configure HID target: " + message);
  }
}

Device::~Device() {
  if (handle_ != nullptr) {
    hid_close(handle_);
  }
}

void Device::FlushInput() {
  std::vector<std::uint8_t> input(kMaximumHidReportSize);
  for (;;) {
    const int result = hid_read_timeout(handle_, input.data(), input.size(), 0);
    if (result == 0) {
      return;
    }
    if (result < 0) {
      throw std::runtime_error("could not flush HID input: " +
                               HidError(handle_));
    }
  }
}

void Device::Write(const std::vector<std::uint8_t> &report) {
  if (report.empty() || report.size() > kMaximumHidReportSize) {
    throw std::invalid_argument("HID output report size is invalid");
  }
  const int written = hid_write(handle_, report.data(), report.size());
  if (written != static_cast<int>(report.size())) {
    throw std::runtime_error("could not write complete HID report: " +
                             HidError(handle_));
  }
}

std::optional<std::vector<std::uint8_t>>
Device::Read(std::chrono::milliseconds timeout) {
  if (timeout.count() < 0 ||
      timeout.count() > std::numeric_limits<int>::max()) {
    throw std::invalid_argument("HID input timeout is invalid");
  }
  std::vector<std::uint8_t> input(kMaximumHidReportSize);
  const int read = hid_read_timeout(handle_, input.data(), input.size(),
                                    static_cast<int>(timeout.count()));
  if (read == 0) {
    return std::nullopt;
  }
  if (read < 0) {
    throw std::runtime_error("could not read HID report: " + HidError(handle_));
  }
  input.resize(static_cast<std::size_t>(read));
  return input;
}
