#include "host_vfs_internal.h"
#include "brovfs/mime.h"
#include "brovfs/volumes.h"

#include <filesystem>

namespace brovfs::api {

void installMiscOnto(Value vfsObj) {
    ObjectBuilder vfs(vfsObj);

    // bro.vfs.getMime(path) -> string
    vfs.def("getMime", 1, [](Value, std::span<const Value> args) -> Value {
        if (args.empty() || !ev::isString(args[0])) {
            return ev::throwError("bro.vfs.getMime requires a path string");
        }
        std::string pathStr = ev::toUtf8(args[0]);
        std::filesystem::path p = std::filesystem::path(pathStr);


        auto ft = bro::vfs::MimeDatabase::system().type_for_file(p);
        if (!ft.mime.empty()) {
            return ev::fromUtf8(ft.mime);
        }
        std::string byName = bro::vfs::MimeDatabase::system().type_for_name(p.filename().string());
        if (!byName.empty()) {
            return ev::fromUtf8(byName);
        }
        return ev::fromUtf8("application/octet-stream");
    });

    // bro.vfs.listVolumes() -> Volume[]
    vfs.def("listVolumes", 0, [](Value, std::span<const Value>) -> Value {
        auto vols = bro::vfs::list_volumes();
        ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(vols.size())));
        for (size_t i = 0; i < vols.size(); ++i) {
            ev::Persistent itemVal(volumeInfoToJs(vols[i]));
            arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), itemVal.get()));
        }
        return arr.get();
    });
}

} // namespace brovfs::api
