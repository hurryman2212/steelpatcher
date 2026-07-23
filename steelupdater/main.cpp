#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "catalog.h"
#include "device.h"
#include "updater.h"

namespace {

const std::filesystem::path kDefaultProgramDirectory =
    R"(C:\Program Files\SteelSeries\GG)";

class HidLifetime {
public:
  HidLifetime() { InitializeHid(); }
  HidLifetime(const HidLifetime &) = delete;
  HidLifetime &operator=(const HidLifetime &) = delete;
  ~HidLifetime() { ShutdownHid(); }
};

void PrintHelp() {
  std::cout
      << "usage: steelupdater [-h] [--version] "
         "{dev-list,check-version,update} ...\n\n"
      << "positional arguments:\n"
      << "  {dev-list,check-version,update}\n"
      << "    dev-list          list connected SteelSeries devices\n"
      << "    check-version     read device or firmware file versions\n"
      << "    update            write stock firmware or a patch bundle\n\n"
      << "options:\n"
      << "  -h, --help          show this help message and exit\n"
      << "  --version           show program version and exit\n";
}

void PrintCommandHelp(std::string_view command) {
  if (command == "dev-list") {
    std::cout << "usage: steelupdater dev-list\n\n"
              << "options:\n"
              << "  -h, --help          show this help message and exit\n";
    return;
  }
  if (command == "check-version") {
    std::cout << "usage: steelupdater check-version --address ADDRESS "
                 "[--program-dir DIR]\n"
              << "   or: steelupdater check-version --firmware FILE "
                 "[--program-dir DIR]\n\n"
              << "options:\n"
              << "  -h, --help          show this help message and exit\n"
              << "  --address ADDRESS   read versions from a connected device\n"
              << "  --firmware FILE     inspect one firmware binary\n"
              << "  --program-dir DIR   GG program directory (default: "
              << kDefaultProgramDirectory.string() << ")\n";
    return;
  }
  std::cout
      << "usage: steelupdater update TARGET FIRMWARE [--program-dir DIR]\n"
      << "   or: steelupdater update TARGET --json PATCH_JSON "
         "[--program-dir DIR]\n\n"
      << "positional arguments:\n"
      << "  TARGET              address or HID path from dev-list\n"
      << "  FIRMWARE            unmarked stock firmware image\n\n"
      << "options:\n"
      << "  -h, --help          show this help message and exit\n"
      << "  --json PATCH_JSON   install a steelpatcher bundle\n"
      << "  --program-dir DIR   GG program directory (default: "
      << kDefaultProgramDirectory.string() << ")\n";
}

struct Arguments {
  std::filesystem::path program_directory = kDefaultProgramDirectory;
  std::optional<std::filesystem::path> patch_json;
  std::optional<std::string> address;
  std::optional<std::filesystem::path> firmware;
  std::vector<std::string> positional;
  bool help = false;
};

Arguments ParseArguments(int argc, char **argv, int start) {
  Arguments result;
  for (int index = start; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "-h" || argument == "--help") {
      result.help = true;
    } else if (argument == "--program-dir") {
      if (++index >= argc) {
        throw std::invalid_argument("--program-dir requires a directory");
      }
      result.program_directory = argv[index];
    } else if (argument == "--json") {
      if (++index >= argc) {
        throw std::invalid_argument("--json requires a patch JSON file");
      }
      if (result.patch_json) {
        throw std::invalid_argument("--json may only be specified once");
      }
      result.patch_json = argv[index];
    } else if (argument == "--address") {
      if (++index >= argc) {
        throw std::invalid_argument("--address requires a device address");
      }
      if (result.address) {
        throw std::invalid_argument("--address may only be specified once");
      }
      result.address = argv[index];
    } else if (argument == "--firmware") {
      if (++index >= argc) {
        throw std::invalid_argument("--firmware requires a file");
      }
      if (result.firmware) {
        throw std::invalid_argument("--firmware may only be specified once");
      }
      result.firmware = argv[index];
    } else if (argument.starts_with('-')) {
      throw std::invalid_argument("unknown option: " + argument);
    } else {
      result.positional.push_back(argument);
    }
  }
  return result;
}

void PrintDevices() {
  std::map<std::pair<std::uint16_t, std::uint16_t>, std::size_t> indices;
  bool found = false;
  for (const DeviceInfo &device : ListFirmwareDevices()) {
    found = true;
    const auto key = std::pair{device.vendor_id, device.product_id};
    const std::string address = FormatDeviceAddress(device, indices[key]++);
    const std::string product =
        device.product.empty() ? "SteelSeries device" : device.product;
    std::cout << address << "  " << product << '\n'
              << "  " << device.path << '\n';
  }
  if (!found) {
    std::cout << "no supported devices found\n";
  }
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc < 2) {
      PrintHelp();
      return 2;
    }
    const std::string command = argv[1];
    if ((command == "-h" || command == "--help") && argc == 2) {
      PrintHelp();
      return 0;
    }
    if (command == "--version" && argc == 2) {
      std::cout << "steelupdater " STEELPATCHER_VERSION << '\n';
      return 0;
    }
    if (command != "dev-list" && command != "check-version" &&
        command != "update") {
      PrintHelp();
      return 2;
    }
    if (command == "dev-list") {
      if (argc == 3 && (std::string_view(argv[2]) == "-h" ||
                        std::string_view(argv[2]) == "--help")) {
        PrintCommandHelp(command);
        return 0;
      }
      if (argc != 2) {
        PrintCommandHelp(command);
        return 2;
      }
      HidLifetime hid;
      PrintDevices();
      return 0;
    }
    const Arguments arguments = ParseArguments(argc, argv, 2);
    if (arguments.help) {
      PrintCommandHelp(command);
      return 0;
    }
    if (command == "check-version") {
      if (!arguments.positional.empty() || arguments.patch_json) {
        throw std::invalid_argument(
            "check-version accepts only --address or --firmware");
      }
      if (arguments.address && arguments.firmware) {
        throw std::invalid_argument(
            "--address and --firmware are mutually exclusive");
      }
      if (!arguments.address && !arguments.firmware) {
        throw std::invalid_argument(
            "exactly one of --address or --firmware is required");
      }
      const Catalog catalog(arguments.program_directory);
      if (arguments.address) {
        HidLifetime hid;
        CheckDeviceVersion(catalog, *arguments.address);
      } else {
        CheckFirmwareVersion(catalog, *arguments.firmware);
      }
      return 0;
    }
    const bool invalid_update =
        (arguments.patch_json && arguments.positional.size() != 1) ||
        (!arguments.patch_json && arguments.positional.size() != 2) ||
        arguments.address || arguments.firmware;
    if (invalid_update) {
      PrintCommandHelp(command);
      return 2;
    }

    HidLifetime hid;
    const Catalog catalog(arguments.program_directory);
    if (arguments.patch_json) {
      UpdatePatchedFirmware(catalog, arguments.positional[0],
                            *arguments.patch_json);
    } else {
      UpdateFirmware(catalog, arguments.positional[0],
                     std::filesystem::path(arguments.positional[1]));
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "steelupdater: " << error.what() << '\n';
    return 1;
  }
}
