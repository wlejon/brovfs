#pragma once

#include <string>

#define BROVFS_VERSION_MAJOR 0
#define BROVFS_VERSION_MINOR 1
#define BROVFS_VERSION_PATCH 0
#define BROVFS_VERSION_STRING "0.1.0"

namespace bro::vfs {

[[nodiscard]] int version_major() noexcept;
[[nodiscard]] int version_minor() noexcept;
[[nodiscard]] int version_patch() noexcept;
[[nodiscard]] std::string version_string();

} // namespace bro::vfs
