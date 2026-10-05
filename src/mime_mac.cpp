// macOS type database: Uniform Type Identifiers. An extension maps to its UTI and the UTI's
// preferred MIME type; a MIME type maps to every UTI carrying it and their extensions; canonical()
// round-trips through the UTI so a sniffed spelling and a name answer agree. Dynamic ("dyn.")
// identifiers mean UTType does not know the tag, and the built-in table answers instead.
#include "src/mime_db.h"

#include <CoreServices/CoreServices.h>

#include <algorithm>
#include <cstring>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations" // UTType C API: still the only C surface

namespace bro::vfs::detail {

namespace {

struct Cf {
    CFTypeRef ref = nullptr;
    explicit Cf(CFTypeRef r) : ref(r) {}
    ~Cf() {
        if (ref) CFRelease(ref);
    }
    Cf(const Cf&) = delete;
    Cf& operator=(const Cf&) = delete;
};

CFStringRef make_cf(std::string_view s) {
    return CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(s.data()), static_cast<CFIndex>(s.size()),
                                   kCFStringEncodingUTF8, false);
}

std::string from_cf(CFStringRef s) {
    if (!s) return {};
    CFIndex len = CFStringGetLength(s);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<size_t>(max), '\0');
    if (!CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8)) return {};
    out.resize(std::strlen(out.c_str()));
    return out;
}

// UTI for a tag; empty when UTType only has a dynamic identifier for it.
std::string uti_for(CFStringRef tag_class, std::string_view tag) {
    Cf t(make_cf(tag));
    if (!t.ref) return {};
    Cf uti(UTTypeCreatePreferredIdentifierForTag(tag_class, static_cast<CFStringRef>(t.ref), nullptr));
    std::string s = from_cf(static_cast<CFStringRef>(uti.ref));
    return s.starts_with("dyn.") ? std::string() : s;
}

std::string preferred_mime(const std::string& uti) {
    Cf u(make_cf(uti));
    if (!u.ref) return {};
    Cf m(UTTypeCopyPreferredTagWithClass(static_cast<CFStringRef>(u.ref), kUTTagClassMIMEType));
    return ascii_lower(from_cf(static_cast<CFStringRef>(m.ref)));
}

class MacDatabase : public TableDatabase {
public:
    MacDatabase() : TableDatabase("UTType", nullptr) {}

    std::vector<std::string> types_for_name(std::string_view file_name) const override {
        std::vector<std::string> out;
        size_t dot = file_name.rfind('.');
        if (dot != std::string_view::npos && dot > 0 && dot + 1 < file_name.size()) {
            std::string uti = uti_for(kUTTagClassFilenameExtension, file_name.substr(dot + 1));
            std::string mime = uti.empty() ? std::string() : preferred_mime(uti);
            if (!mime.empty()) out.push_back(canonical(mime));
        }
        for (auto& m : TableDatabase::types_for_name(file_name)) {
            if (std::find(out.begin(), out.end(), m) == out.end()) out.push_back(std::move(m));
        }
        return out;
    }

    std::vector<std::string> extensions_for_type(std::string_view mime) const override {
        std::vector<std::string> out;
        for (const std::string& spelling : {canonical(mime), ascii_lower(mime)}) {
            Cf tag(make_cf(spelling));
            if (!tag.ref) continue;
            Cf utis(UTTypeCreateAllIdentifiersForTag(kUTTagClassMIMEType, static_cast<CFStringRef>(tag.ref), nullptr));
            if (!utis.ref) continue;
            auto arr = static_cast<CFArrayRef>(utis.ref);
            for (CFIndex i = 0; i < CFArrayGetCount(arr); ++i) {
                auto uti = static_cast<CFStringRef>(CFArrayGetValueAtIndex(arr, i));
                if (from_cf(uti).starts_with("dyn.")) continue;
                Cf exts(UTTypeCopyAllTagsWithClass(uti, kUTTagClassFilenameExtension));
                if (!exts.ref) continue;
                auto ea = static_cast<CFArrayRef>(exts.ref);
                for (CFIndex j = 0; j < CFArrayGetCount(ea); ++j) {
                    std::string e = ascii_lower(from_cf(static_cast<CFStringRef>(CFArrayGetValueAtIndex(ea, j))));
                    if (!e.empty() && std::find(out.begin(), out.end(), e) == out.end()) out.push_back(std::move(e));
                }
            }
        }
        for (auto& e : TableDatabase::extensions_for_type(mime)) {
            if (std::find(out.begin(), out.end(), e) == out.end()) out.push_back(std::move(e));
        }
        return out;
    }

    std::string canonical(std::string_view mime) const override {
        std::string b = TableDatabase::canonical(mime);
        if (b.empty()) return b;
        std::string uti = uti_for(kUTTagClassMIMEType, b);
        if (uti.empty()) return b;
        std::string p = preferred_mime(uti);
        return p.empty() ? b : p;
    }
};

} // namespace

std::unique_ptr<MimeDatabase> make_platform_database() {
    return std::make_unique<MacDatabase>();
}

} // namespace bro::vfs::detail

#pragma clang diagnostic pop
