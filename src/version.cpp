#include "brovfs/version.h"

namespace bro::vfs {

int version_major() noexcept {
    return BROVFS_VERSION_MAJOR;
}

int version_minor() noexcept {
    return BROVFS_VERSION_MINOR;
}

int version_patch() noexcept {
    return BROVFS_VERSION_PATCH;
}

std::string version_string() {
    return BROVFS_VERSION_STRING;
}

} // namespace bro::vfs
