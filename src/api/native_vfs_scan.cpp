#include "host_vfs_internal.h"
#include "brovfs/scanner.h"

namespace brovfs::api {

void installScanOnto(Value vfsObj) {
    ObjectBuilder vfs(vfsObj);

    vfs.def("scan", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.empty() || !ev::isString(args[0])) {
            ev::Persistent err(makeError("bro.vfs.scan requires a directory path as the first argument"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string pathStr = ev::toUtf8(args[0]);
        bro::vfs::ScanOptions scanOpts;

        if (args.size() > 1 && ev::isObject(args[1])) {
            ev::Persistent opt(args[1]);
            Value recVal = ev::getProperty(opt.get(), "recursive");
            if (ev::isBool(recVal)) scanOpts.recursive = ev::toBool(recVal);

            Value maxDVal = ev::getProperty(opt.get(), "maxDepth");
            if (ev::isNumber(maxDVal)) {
                double d = ev::toDouble(maxDVal);
                if (d >= 0.0) scanOpts.max_depth = static_cast<uint32_t>(d);
            }

            Value hidVal = ev::getProperty(opt.get(), "includeHidden");
            if (ev::isBool(hidVal)) scanOpts.include_hidden = ev::toBool(hidVal);
        }

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resultPtr = std::make_shared<bro::vfs::ScanResult>();
        job->run = [pathStr, scanOpts, resultPtr]() {
            *resultPtr = bro::vfs::scan_directory(std::filesystem::path(pathStr), scanOpts);
        };


        job->settle = [resultPtr](Value pVal) {
            if (!resultPtr->errors.empty() && resultPtr->entries.empty()) {
                const auto& firstErr = resultPtr->errors[0];
                std::string msg = "Scan failed for " + firstErr.path.string() + ": " + firstErr.code.message();
                ev::Persistent err(makeError(msg));
                ev::rejectPromise(pVal, err.get());
                return;
            }

            ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(resultPtr->entries.size())));
            for (size_t i = 0; i < resultPtr->entries.size(); ++i) {
                ev::Persistent itemVal(entryToJs(resultPtr->entries[i]));
                arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), itemVal.get()));
            }
            ev::resolvePromise(pVal, arr.get());
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });
}

} // namespace brovfs::api
