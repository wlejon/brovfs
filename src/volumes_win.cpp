#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "src/volumes_internal.h"
#include <string>
#include <vector>

namespace bro::vfs::detail {

namespace {

std::string wide_to_utf8(const wchar_t* wstr) {
    if (!wstr || !*wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result.data(), len - 1, nullptr, nullptr);
    return result;
}

} // namespace

std::vector<VolumeInfo> list_volumes_platform() {
    std::vector<VolumeInfo> volumes;

    DWORD buffer_len = GetLogicalDriveStringsW(0, nullptr);
    if (buffer_len == 0) {
        return volumes;
    }

    std::vector<wchar_t> buffer(buffer_len + 1, L'\0');
    if (GetLogicalDriveStringsW(buffer_len, buffer.data()) == 0) {
        return volumes;
    }

    const wchar_t* drive_ptr = buffer.data();
    while (*drive_ptr) {
        std::wstring drive = drive_ptr;
        drive_ptr += drive.size() + 1;

        UINT drive_type = GetDriveTypeW(drive.c_str());
        if (drive_type == DRIVE_NO_ROOT_DIR) {
            continue;
        }

        VolumeInfo info;
        info.mount_point = wide_to_utf8(drive.c_str());
        // Normalize mount point with forward slash if needed, or keep standard C:\

        if (drive_type == DRIVE_REMOVABLE) {
            info.is_removable = true;
        } else if (drive_type == DRIVE_REMOTE) {
            info.is_network = true;
        } else if (drive_type == DRIVE_CDROM) {
            info.is_removable = true;
            info.is_read_only = true;
        }

        wchar_t volume_name_buf[MAX_PATH + 1] = {0};
        wchar_t fs_name_buf[MAX_PATH + 1] = {0};
        DWORD serial_number = 0;
        DWORD max_component_len = 0;
        DWORD flags = 0;

        // Prevent error popups for empty optical / floppy drives
        UINT old_mode = SetErrorMode(SEM_FAILCRITICALERRORS);

        if (GetVolumeInformationW(
                drive.c_str(),
                volume_name_buf,
                MAX_PATH + 1,
                &serial_number,
                &max_component_len,
                &flags,
                fs_name_buf,
                MAX_PATH + 1))
        {
            info.volume_label = wide_to_utf8(volume_name_buf);
            info.fs_type = wide_to_utf8(fs_name_buf);
            if (flags & FILE_READ_ONLY_VOLUME) {
                info.is_read_only = true;
            }
        }

        ULARGE_INTEGER free_bytes_available;
        ULARGE_INTEGER total_number_of_bytes;
        ULARGE_INTEGER total_number_of_free_bytes;

        if (GetDiskFreeSpaceExW(
                drive.c_str(),
                &free_bytes_available,
                &total_number_of_bytes,
                &total_number_of_free_bytes))
        {
            info.available_bytes = free_bytes_available.QuadPart;
            info.total_bytes = total_number_of_bytes.QuadPart;
            info.free_bytes = total_number_of_free_bytes.QuadPart;
        }

        SetErrorMode(old_mode);

        volumes.push_back(std::move(info));
    }

    return volumes;
}

} // namespace bro::vfs::detail

#endif // _WIN32
