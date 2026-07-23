#ifndef STEELPATCHER_STEELUPDATER_CONTAINER_H_
#define STEELPATCHER_STEELUPDATER_CONTAINER_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

struct SteelpatchContainer {
  std::vector<std::uint8_t> payload;
  nlohmann::json metadata;
};

std::string Sha256Hex(const std::vector<std::uint8_t> &bytes);
std::optional<SteelpatchContainer>
ParseSteelpatchContainer(const std::vector<std::uint8_t> &bytes);

#endif
