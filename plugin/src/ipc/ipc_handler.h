#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace deobf {

std::string handleCommand(const std::string& json_str);

} // namespace deobf
