// MimeDatabase: glob tables, the table-backed database, name/content reconciliation.
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS // getenv
#endif
#include "src/mime_db.h"

#include "brovfs/path.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <unordered_set>

namespace bro::vfs {

namespace detail {

std::string ascii_lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

namespace {

bool has_wildcard(std::string_view p) { return p.find_first_of("*?[") != std::string_view::npos; }

// Matches one bracket expression at p[0] == '['; returns the index after ']' or npos when the
// expression is malformed (then '[' is treated as a literal).
size_t match_bracket(std::string_view p, char c, bool& matched) {
    size_t i = 1;
    bool negate = i < p.size() && (p[i] == '!' || p[i] == '^');
    if (negate) ++i;
    bool any = false;
    bool first = true;
    while (i < p.size() && (p[i] != ']' || first)) {
        first = false;
        char lo = p[i];
        char hi = lo;
        if (i + 2 < p.size() && p[i + 1] == '-' && p[i + 2] != ']') {
            hi = p[i + 2];
            i += 3;
        } else {
            ++i;
        }
        if (c >= lo && c <= hi) any = true;
    }
    if (i >= p.size()) return std::string_view::npos;
    matched = any != negate;
    return i + 1;
}

} // namespace

bool glob_match(std::string_view p, std::string_view s) {
    size_t pi = 0, si = 0;
    size_t star_p = std::string_view::npos, star_s = 0;
    while (si < s.size()) {
        if (pi < p.size() && p[pi] == '*') {
            star_p = pi++;
            star_s = si;
            continue;
        }
        if (pi < p.size()) {
            if (p[pi] == '?') {
                ++pi;
                ++si;
                continue;
            }
            if (p[pi] == '[') {
                bool m = false;
                size_t next = match_bracket(p.substr(pi), s[si], m);
                if (next != std::string_view::npos) {
                    if (m) {
                        pi += next;
                        ++si;
                        continue;
                    }
                } else if (s[si] == '[') {
                    ++pi;
                    ++si;
                    continue;
                }
            } else if (p[pi] == s[si]) {
                ++pi;
                ++si;
                continue;
            }
        }
        if (star_p == std::string_view::npos) return false;
        pi = star_p + 1;
        si = ++star_s;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

void TypeTable::add_glob(std::string_view pattern, std::string_view mime, int weight, bool case_sensitive) {
    if (pattern.empty() || mime.empty()) return;
    GlobRule r;
    r.pattern = case_sensitive ? std::string(pattern) : ascii_lower(pattern);
    r.mime = ascii_lower(mime);
    r.weight = weight;
    r.case_sensitive = case_sensitive;
    r.order = next_order_++;
    if (!has_wildcard(pattern)) {
        literals_[r.pattern].push_back(std::move(r));
    } else if (pattern[0] == '*' && !has_wildcard(pattern.substr(1)) && pattern.size() > 1) {
        std::string key = r.pattern.substr(1);
        suffixes_[key].push_back(std::move(r));
    } else {
        complex_.push_back(std::move(r));
    }
}

void TypeTable::add_alias(std::string_view alias, std::string_view canonical) {
    aliases_.try_emplace(ascii_lower(alias), ascii_lower(canonical));
}

void TypeTable::add_parent(std::string_view child, std::string_view parent) {
    auto& v = parents_[ascii_lower(child)];
    std::string p = ascii_lower(parent);
    if (std::find(v.begin(), v.end(), p) == v.end()) v.push_back(std::move(p));
}

void TypeTable::clear_globs(std::string_view mime) {
    std::string m = ascii_lower(mime);
    auto drop = [&](std::vector<GlobRule>& v) {
        v.erase(std::remove_if(v.begin(), v.end(), [&](const GlobRule& r) { return r.mime == m; }), v.end());
    };
    for (auto& [k, v] : literals_) drop(v);
    for (auto& [k, v] : suffixes_) drop(v);
    drop(complex_);
}

void TypeTable::collect(std::string_view name, bool literal_pass, std::vector<Hit>& hits) const {
    std::string lower = ascii_lower(name);
    auto take = [&](const std::vector<GlobRule>& rules, bool exact_key) {
        for (const auto& r : rules) {
            // A case-sensitive rule only counts when the exact spelling matched.
            if (r.case_sensitive && !exact_key) continue;
            hits.push_back({&r, r.pattern.size()});
        }
    };
    if (literal_pass) {
        if (auto it = literals_.find(lower); it != literals_.end()) take(it->second, lower == name);
        if (lower != name) {
            if (auto it = literals_.find(std::string(name)); it != literals_.end()) take(it->second, true);
        }
        return;
    }
    for (size_t i = 1; i < name.size(); ++i) {
        if (auto it = suffixes_.find(lower.substr(i)); it != suffixes_.end()) {
            take(it->second, name.substr(i) == lower.substr(i));
        }
        if (name.substr(i) != lower.substr(i)) {
            if (auto it = suffixes_.find(std::string(name.substr(i))); it != suffixes_.end()) take(it->second, true);
        }
    }
    for (const auto& r : complex_) {
        if (glob_match(r.pattern, r.case_sensitive ? std::string(name) : lower)) hits.push_back({&r, r.pattern.size()});
    }
}

std::vector<std::string> TypeTable::match(std::string_view name) const {
    std::vector<Hit> hits;
    collect(name, true, hits);
    if (hits.empty()) collect(name, false, hits);
    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) {
        if (a.rule->weight != b.rule->weight) return a.rule->weight > b.rule->weight;
        if (a.length != b.length) return a.length > b.length;
        return a.rule->order < b.rule->order;
    });
    std::vector<std::string> out;
    for (const auto& h : hits) {
        if (std::find(out.begin(), out.end(), h.rule->mime) == out.end()) out.push_back(h.rule->mime);
    }
    return out;
}

std::vector<std::string> TypeTable::extensions(std::string_view mime) const {
    std::vector<const GlobRule*> rules;
    for (const auto& [key, v] : suffixes_) {
        if (key.size() < 2 || key[0] != '.') continue;
        for (const auto& r : v) {
            if (r.mime == mime) rules.push_back(&r);
        }
    }
    std::sort(rules.begin(), rules.end(), [](const GlobRule* a, const GlobRule* b) {
        if (a->weight != b->weight) return a->weight > b->weight;
        return a->order < b->order;
    });
    std::vector<std::string> out;
    for (const auto* r : rules) {
        std::string ext = r->pattern.substr(2);
        if (std::find(out.begin(), out.end(), ext) == out.end()) out.push_back(std::move(ext));
    }
    return out;
}

const std::string* TypeTable::alias_target(std::string_view mime) const {
    auto it = aliases_.find(std::string(mime));
    return it == aliases_.end() ? nullptr : &it->second;
}

const std::vector<std::string>* TypeTable::parents(std::string_view mime) const {
    auto it = parents_.find(std::string(mime));
    return it == parents_.end() ? nullptr : &it->second;
}

namespace {

std::string strip_params(std::string_view mime) {
    size_t semi = mime.find(';');
    if (semi != std::string_view::npos) mime = mime.substr(0, semi);
    while (!mime.empty() && std::isspace(static_cast<unsigned char>(mime.back()))) mime.remove_suffix(1);
    while (!mime.empty() && std::isspace(static_cast<unsigned char>(mime.front()))) mime.remove_prefix(1);
    return ascii_lower(mime);
}

void merge_unique(std::vector<std::string>& into, std::vector<std::string> from) {
    for (auto& s : from) {
        if (std::find(into.begin(), into.end(), s) == into.end()) into.push_back(std::move(s));
    }
}

} // namespace

TableDatabase::TableDatabase(std::string_view backend, const TypeTable* primary)
    : backend_(backend), primary_(primary) {}

std::string TableDatabase::builtin_canonical(std::string_view mime) {
    std::string m = strip_params(mime);
    if (const auto* t = builtin_table().alias_target(m)) return *t;
    return m;
}

std::vector<std::string> TableDatabase::builtin_types_for_name(std::string_view file_name) {
    return builtin_table().match(file_name);
}

std::vector<std::string> TableDatabase::types_for_name(std::string_view file_name) const {
    std::vector<std::string> raw;
    if (primary_) raw = primary_->match(file_name);
    if (raw.empty()) raw = builtin_types_for_name(file_name);
    std::vector<std::string> out;
    for (const auto& m : raw) merge_unique(out, {canonical(m)});
    return out;
}

std::vector<std::string> TableDatabase::extensions_for_type(std::string_view mime) const {
    std::string c = canonical(mime);
    std::vector<std::string> out;
    if (primary_) out = primary_->extensions(c);
    merge_unique(out, builtin_table().extensions(c));
    std::string b = builtin_canonical(mime);
    if (b != c) merge_unique(out, builtin_table().extensions(b));
    return out;
}

std::string TableDatabase::canonical(std::string_view mime) const {
    std::string m = strip_params(mime);
    if (primary_) {
        if (const auto* t = primary_->alias_target(m)) return *t;
    }
    if (const auto* t = builtin_table().alias_target(m)) {
        if (primary_) {
            if (const auto* t2 = primary_->alias_target(*t)) return *t2;
        }
        return *t;
    }
    return m;
}

bool TableDatabase::parents_of(const std::string& mime, std::vector<std::string>& out) const {
    size_t before = out.size();
    auto add = [&](const std::vector<std::string>* v) {
        if (!v) return;
        for (const auto& p : *v) out.push_back(canonical(p));
    };
    if (primary_) add(primary_->parents(mime));
    add(builtin_table().parents(mime));
    std::string b = builtin_canonical(mime);
    if (b != mime) add(builtin_table().parents(b));
    auto ends_with = [&](std::string_view suffix) {
        return mime.size() > suffix.size() && mime.compare(mime.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    if (ends_with("+xml")) out.push_back(canonical("application/xml"));
    if (ends_with("+json")) out.push_back(canonical("application/json"));
    if (ends_with("+zip")) out.push_back(canonical("application/zip"));
    if (mime.starts_with("text/") && mime != "text/plain") out.push_back("text/plain");
    return out.size() > before;
}

bool TableDatabase::is_a(std::string_view mime, std::string_view ancestor) const {
    std::string m = canonical(mime);
    std::string a = canonical(ancestor);
    if (m.empty() || a.empty()) return false;
    if (m == a) return true;
    if (a == "application/octet-stream") return !m.starts_with("inode/");
    std::vector<std::string> todo{m};
    std::unordered_set<std::string> seen{m};
    while (!todo.empty()) {
        std::string cur = std::move(todo.back());
        todo.pop_back();
        std::vector<std::string> ps;
        parents_of(cur, ps);
        for (auto& p : ps) {
            if (p == a) return true;
            if (seen.insert(p).second) todo.push_back(std::move(p));
        }
    }
    return false;
}

} // namespace detail

// ---- MimeDatabase ------------------------------------------------------------------------------

namespace {

constexpr std::string_view kOctet = "application/octet-stream";

std::string leaf_utf8(std::string_view name) {
    size_t slash = name.find_last_of("/\\");
    return std::string(slash == std::string_view::npos ? name : name.substr(slash + 1));
}

} // namespace

std::string MimeDatabase::type_for_name(std::string_view file_name) const {
    auto v = types_for_name(leaf_utf8(file_name));
    return v.empty() ? std::string() : v.front();
}

std::string MimeDatabase::type_for_extension(std::string_view ext) const {
    if (!ext.empty() && ext.front() == '.') ext.remove_prefix(1);
    if (ext.empty() || ext.find_first_of("/\\") != std::string_view::npos) return std::string(kOctet);
    std::string t = type_for_name("x." + std::string(ext));
    return t.empty() ? std::string(kOctet) : t;
}

FileType MimeDatabase::type_for_data(std::string_view file_name, std::span<const uint8_t> head,
                                     bool have_content) const {
    FileType ft;
    auto names = types_for_name(leaf_utf8(file_name));
    if (!names.empty()) ft.by_name = names.front();

    auto by_name_only = [&]() {
        ft.mime = ft.by_name.empty() ? std::string(kOctet) : ft.by_name;
        ft.basis = ft.by_name.empty() ? TypeBasis::None : TypeBasis::Name;
        return ft;
    };
    if (!have_content) return by_name_only();

    std::string sniffed = sniff_mime_type(head);
    ft.by_content = canonical(sniffed);
    const std::string& c = ft.by_content;

    // Uninformative content: the name decides when it says anything.
    if (sniffed == "application/octet-stream" || sniffed == "application/x-empty") {
        if (!ft.by_name.empty()) return by_name_only();
        ft.mime = c;
        ft.basis = TypeBasis::Content;
        return ft;
    }
    // A name candidate that is the content type or a more specific kind of it.
    for (const auto& n : names) {
        if (n == c || is_a(n, c)) {
            ft.mime = n;
            ft.basis = TypeBasis::Both;
            return ft;
        }
    }
    // A signature (or plain text) the name contradicts: the content is what the file is.
    ft.mime = c;
    ft.basis = TypeBasis::Content;
    return ft;
}

FileType MimeDatabase::type_for_file(const std::filesystem::path& path) const {
    std::string name = path_to_utf8(path.filename());
    std::error_code ec;
    auto st = std::filesystem::status(path, ec);
    if (!ec && std::filesystem::is_directory(st)) {
        FileType ft;
        ft.mime = ft.by_content = canonical("inode/directory");
        ft.basis = TypeBasis::Content;
        return ft;
    }
    if (ec || !std::filesystem::exists(st)) return type_for_data(name, {}, false);

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return type_for_data(name, {}, false);
    uint8_t buf[512];
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    std::streamsize got = f.gcount();
    if (got < 0) got = 0;
    return type_for_data(name, std::span<const uint8_t>(buf, static_cast<size_t>(got)), true);
}

const MimeDatabase& MimeDatabase::built_in() {
    static const detail::TableDatabase db("built-in", nullptr);
    return db;
}

std::vector<std::filesystem::path> MimeDatabase::xdg_mime_dirs() {
    std::vector<std::filesystem::path> dirs;
    auto env = [](const char* n) -> std::string {
        const char* v = std::getenv(n);
        return v ? std::string(v) : std::string();
    };
    std::string home = env("XDG_DATA_HOME");
    if (home.empty() && !env("HOME").empty()) home = env("HOME") + "/.local/share";
    if (!home.empty()) dirs.push_back(path_from_utf8(home) / "mime");
    std::string data = env("XDG_DATA_DIRS");
    if (data.empty()) data = "/usr/local/share/:/usr/share/";
    size_t start = 0;
    while (start <= data.size()) {
        size_t colon = data.find(':', start);
        std::string d = data.substr(start, colon == std::string::npos ? std::string::npos : colon - start);
        if (!d.empty()) dirs.push_back(path_from_utf8(d) / "mime");
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return dirs;
}

const MimeDatabase& MimeDatabase::system() {
    static const std::unique_ptr<MimeDatabase> db = []() -> std::unique_ptr<MimeDatabase> {
#if defined(_WIN32) || defined(__APPLE__)
        if (auto p = detail::make_platform_database()) return p;
#else
        std::error_code ec;
        if (auto p = load_shared_mime_info(xdg_mime_dirs(), ec)) return p;
#endif
        return std::make_unique<detail::TableDatabase>("built-in", nullptr);
    }();
    return *db;
}

std::string extension_to_mime(std::string_view ext) {
    return MimeDatabase::built_in().type_for_extension(ext);
}

std::string mime_to_extension(std::string_view mime_type) {
    auto v = MimeDatabase::built_in().extensions_for_type(mime_type);
    return v.empty() ? std::string("bin") : v.front();
}

} // namespace bro::vfs
