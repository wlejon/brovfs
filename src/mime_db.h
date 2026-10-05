#pragma once
// MimeDatabase internals: a glob/alias/subclass table (built-in or loaded from shared-mime-info)
// and the database class every backend derives from.

#include "brovfs/mime.h"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace bro::vfs::detail {

std::string ascii_lower(std::string_view s);

// fnmatch subset used by shared-mime-info globs: '*', '?', '[...]' (with '!' / '^' negation and
// ranges). No escapes, no path semantics.
bool glob_match(std::string_view pattern, std::string_view name);

struct GlobRule {
    std::string pattern;   // lower-cased unless case_sensitive
    std::string mime;
    int weight = 50;
    bool case_sensitive = false;
    size_t order = 0;      // load order: earlier wins ties (higher-priority directory first)
};

class TypeTable {
public:
    void add_glob(std::string_view pattern, std::string_view mime, int weight, bool case_sensitive);
    void add_alias(std::string_view alias, std::string_view canonical);
    void add_parent(std::string_view child, std::string_view parent);
    // Drops every glob for `mime` added so far (shared-mime-info's __NOGLOBS__).
    void clear_globs(std::string_view mime);

    [[nodiscard]] std::vector<std::string> match(std::string_view file_name) const;
    [[nodiscard]] std::vector<std::string> extensions(std::string_view canonical_mime) const;
    [[nodiscard]] const std::string* alias_target(std::string_view mime) const;
    [[nodiscard]] const std::vector<std::string>* parents(std::string_view mime) const;
    [[nodiscard]] bool empty() const { return literals_.empty() && suffixes_.empty() && complex_.empty(); }

private:
    struct Hit { const GlobRule* rule; size_t length; };
    void collect(std::string_view name, bool literal_pass, std::vector<Hit>& hits) const;

    size_t next_order_ = 0;
    // Literal names, "*.<plain suffix>" and everything else, each keyed for fast lookup.
    std::unordered_map<std::string, std::vector<GlobRule>> literals_;
    std::unordered_map<std::string, std::vector<GlobRule>> suffixes_; // key: suffix after "*"
    std::vector<GlobRule> complex_;
    std::unordered_map<std::string, std::string> aliases_;
    std::unordered_map<std::string, std::vector<std::string>> parents_;
};

// The built-in table (src/mime_builtin.cpp).
const TypeTable& builtin_table();

// A database over one TypeTable, consulting the built-in table for anything the primary table
// does not answer. Platform backends override the name / extension / canonical lookups.
class TableDatabase : public MimeDatabase {
public:
    TableDatabase(std::string_view backend, const TypeTable* primary);

    std::string_view backend() const noexcept override { return backend_; }
    std::vector<std::string> types_for_name(std::string_view file_name) const override;
    std::vector<std::string> extensions_for_type(std::string_view mime) const override;
    std::string canonical(std::string_view mime) const override;
    bool is_a(std::string_view mime, std::string_view ancestor) const override;

protected:
    // Built-in only: canonical spelling and name matches.
    static std::string builtin_canonical(std::string_view mime);
    static std::vector<std::string> builtin_types_for_name(std::string_view file_name);

private:
    bool parents_of(const std::string& mime, std::vector<std::string>& out) const;

    std::string backend_;
    const TypeTable* primary_; // null: built-in only
};

std::unique_ptr<MimeDatabase> make_platform_database(); // Windows / macOS; null elsewhere

} // namespace bro::vfs::detail
