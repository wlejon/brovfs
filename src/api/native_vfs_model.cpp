#include "host_vfs_internal.h"
#include "brovfs/dir_model.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <mutex>
#include <vector>

namespace brovfs::api {

HostClass g_directoryModelClass;

namespace {

struct WrappedModel {
    std::shared_ptr<bro::vfs::DirectoryModel> model;
    std::vector<std::unique_ptr<ev::Persistent>> change_callbacks;
    bool show_hidden = false;
};

std::mutex g_model_mu;
std::vector<std::shared_ptr<WrappedModel>> g_active_models;

std::string strToLower(std::string_view sv) {
    std::string s;
    s.reserve(sv.size());
    for (char c : sv) {
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return s;
}

Value modelItemToJs(const bro::vfs::ModelItem& item) {


    ObjectBuilder b(entryToJs(item.entry));
    b.set("key", static_cast<double>(item.key));
    return b.get();
}

Value entriesToArray(const std::vector<bro::vfs::ModelItem>& items) {
    ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(items.size())));
    for (size_t i = 0; i < items.size(); ++i) {
        ev::Persistent itemVal(modelItemToJs(items[i]));
        arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), itemVal.get()));
    }
    return arr.get();
}

} // namespace

void drainModelUpdates() {
    std::vector<std::shared_ptr<WrappedModel>> models;
    {
        std::lock_guard lock(g_model_mu);
        models = g_active_models;
    }

    for (auto& wrapped : models) {
        if (!wrapped || !wrapped->model) continue;
        auto updates = wrapped->model->queue()->drain();
        if (updates.empty()) continue;

        if (wrapped->change_callbacks.empty()) continue;

        auto snapshot = wrapped->model->snapshot();
        ev::Persistent entriesArr(entriesToArray(snapshot.items));
        const Value arg = entriesArr.get();

        for (auto& cb : wrapped->change_callbacks) {
            if (cb && ev::isFunction(cb->get())) {
                ev::call(cb->get(), ev::undefined(), std::span<const Value>(&arg, 1));
            }
        }
    }
}

void clearModels() {
    std::lock_guard lock(g_model_mu);
    g_active_models.clear();
}

void installModelOnto(Value vfsObj) {
    g_directoryModelClass.install("DirectoryModel", 1, [](Value, std::span<const Value> args) -> Value {
        if (args.empty() || !ev::isString(args[0])) {
            return ev::throwError("DirectoryModel constructor requires a directory path as the first argument");
        }

        std::string pathStr = ev::toUtf8(args[0]);
        std::filesystem::path dirPath = std::filesystem::path(pathStr);


        bro::vfs::ModelOptions opts;
        if (args.size() > 1 && ev::isObject(args[1])) {
            ev::Persistent opt(args[1]);

            Value hidVal = ev::getProperty(opt.get(), "showHidden");
            if (ev::isBool(hidVal)) opts.show_hidden = ev::toBool(hidVal);

            Value watchVal = ev::getProperty(opt.get(), "watch");
            if (ev::isBool(watchVal)) opts.watch = ev::toBool(watchVal);

            Value latVal = ev::getProperty(opt.get(), "latency");
            if (ev::isNumber(latVal)) {
                double ms = ev::toDouble(latVal);
                if (ms >= 0.0) opts.latency = std::chrono::milliseconds(static_cast<int64_t>(ms));
            }

            Value sortVal = ev::getProperty(opt.get(), "sort");
            if (ev::isObject(sortVal)) {
                ev::Persistent s(sortVal);
                Value fieldVal = ev::getProperty(s.get(), "field");
                if (ev::isString(fieldVal)) {
                    std::string f = ev::toUtf8(fieldVal);
                    if (f == "size") opts.sort.field = bro::vfs::SortField::Size;
                    else if (f == "modified") opts.sort.field = bro::vfs::SortField::Modified;
                    else if (f == "type") opts.sort.field = bro::vfs::SortField::Type;
                    else if (f == "kind") opts.sort.field = bro::vfs::SortField::Kind;
                    else opts.sort.field = bro::vfs::SortField::Name;
                }
                Value ascVal = ev::getProperty(s.get(), "ascending");
                if (ev::isBool(ascVal)) opts.sort.descending = !ev::toBool(ascVal);

                Value dfVal = ev::getProperty(s.get(), "directoriesFirst");
                if (ev::isBool(dfVal)) opts.sort.directories_first = ev::toBool(dfVal);
            }
        }

        auto nativeModel = std::make_shared<bro::vfs::DirectoryModel>(dirPath, opts);
        auto wrapped = std::make_shared<WrappedModel>();
        wrapped->model = nativeModel;
        wrapped->show_hidden = opts.show_hidden;

        {
            std::lock_guard lock(g_model_mu);
            g_active_models.push_back(wrapped);
        }

        auto wrappedPtr = new std::shared_ptr<WrappedModel>(wrapped);
        return g_directoryModelClass.make(wrappedPtr, [](void* ptr) {
            auto p = static_cast<std::shared_ptr<WrappedModel>*>(ptr);
            delete p;
        });
    }, [](ObjectBuilder& proto) {
        // entries() -> Entry[]
        proto.def("entries", 0, [](Value self, std::span<const Value>) -> Value {
            auto wrappedPtr = static_cast<std::shared_ptr<WrappedModel>*>(g_directoryModelClass.unwrap(self));
            if (!wrappedPtr || !*wrappedPtr || !(*wrappedPtr)->model) {
                return ev::makeArray(0);
            }
            auto snapshot = (*wrappedPtr)->model->snapshot();
            return entriesToArray(snapshot.items);
        });

        // setSort(field: string, ascending?: boolean)
        proto.def("setSort", 1, [](Value self, std::span<const Value> args) -> Value {
            auto wrappedPtr = static_cast<std::shared_ptr<WrappedModel>*>(g_directoryModelClass.unwrap(self));
            if (!wrappedPtr || !*wrappedPtr || !(*wrappedPtr)->model) return self;

            if (args.empty() || !ev::isString(args[0])) {
                return ev::throwError("setSort requires a field string");
            }

            std::string fieldStr = ev::toUtf8(args[0]);
            bool ascending = true;
            if (args.size() > 1 && ev::isBool(args[1])) {
                ascending = ev::toBool(args[1]);
            }

            bro::vfs::SortSpec spec;
            if (fieldStr == "size") spec.field = bro::vfs::SortField::Size;
            else if (fieldStr == "modified") spec.field = bro::vfs::SortField::Modified;
            else if (fieldStr == "type") spec.field = bro::vfs::SortField::Type;
            else if (fieldStr == "kind") spec.field = bro::vfs::SortField::Kind;
            else spec.field = bro::vfs::SortField::Name;

            spec.descending = !ascending;
            spec.directories_first = true;

            (*wrappedPtr)->model->set_sort(spec);
            return self;
        });

        // setFilter(query?: string)
        proto.def("setFilter", 1, [](Value self, std::span<const Value> args) -> Value {
            auto wrappedPtr = static_cast<std::shared_ptr<WrappedModel>*>(g_directoryModelClass.unwrap(self));
            if (!wrappedPtr || !*wrappedPtr || !(*wrappedPtr)->model) return self;

            if (args.empty() || ev::isUndefined(args[0]) || ev::isNull(args[0])) {
                (*wrappedPtr)->model->set_filter(nullptr, (*wrappedPtr)->show_hidden);
                return self;
            }

            std::string q = ev::toUtf8(args[0]);
            if (q.empty()) {
                (*wrappedPtr)->model->set_filter(nullptr, (*wrappedPtr)->show_hidden);
                return self;
            }

            std::string qLower = strToLower(q);
            (*wrappedPtr)->model->set_filter([qLower](const bro::vfs::FileEntry& e) {
                std::string nameLower = strToLower(e.name);
                return nameLower.find(qLower) != std::string::npos;
            }, (*wrappedPtr)->show_hidden);

            return self;
        });

        // refresh()
        proto.def("refresh", 0, [](Value self, std::span<const Value>) -> Value {
            auto wrappedPtr = static_cast<std::shared_ptr<WrappedModel>*>(g_directoryModelClass.unwrap(self));
            if (wrappedPtr && *wrappedPtr && (*wrappedPtr)->model) {
                (*wrappedPtr)->model->refresh();
            }
            return self;
        });

        // on(event: string, callback: function)
        proto.def("on", 2, [](Value self, std::span<const Value> args) -> Value {
            auto wrappedPtr = static_cast<std::shared_ptr<WrappedModel>*>(g_directoryModelClass.unwrap(self));
            if (!wrappedPtr || !*wrappedPtr) return self;

            if (args.size() < 2 || !ev::isString(args[0]) || !ev::isFunction(args[1])) {
                return ev::throwError("on requires (event: string, callback: function)");
            }

            std::string eventName = ev::toUtf8(args[0]);
            if (eventName == "change") {
                (*wrappedPtr)->change_callbacks.push_back(std::make_unique<ev::Persistent>(args[1]));
            }
            return self;
        });
    });

    ObjectBuilder vfs(vfsObj);
    vfs.set("DirectoryModel", g_directoryModelClass.constructor());
}

} // namespace brovfs::api
