#ifndef STEELPATCHER_STEELUPDATER_UPDATER_H_
#define STEELPATCHER_STEELUPDATER_UPDATER_H_

#include <filesystem>

#include "catalog.h"

void CheckDeviceVersion(const Catalog &catalog,
                        const std::string &device_address);
void CheckFirmwareVersion(const Catalog &catalog,
                          const std::filesystem::path &firmware_path);
void UpdateFirmware(const Catalog &catalog, const std::string &device_address,
                    const std::filesystem::path &firmware_path);
void UpdatePatchedFirmware(const Catalog &catalog,
                           const std::string &device_address,
                           const std::filesystem::path &report_path);

#endif
