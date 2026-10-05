#include "src/dir_model_view.h"

#include "brovfs/collate.h"

#include <algorithm>
#include <unordered_set>

namespace bro::vfs::detail {

namespace {

bool dir_like(const FileEntry& e) { return e.kind == FileKind::Directory || e.link_is_directory; }

// Lower-cased ASCII extension of a name ("" for none and for dot files like ".bashrc").
std::string extension(const std::string& name) {
    size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot == 0) return {};
    std::string ext = name.substr(dot + 1);
    for (auto& c : ext) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return ext;
}

template <class T>
int cmp(T a, T b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

} // namespace

bool same_entry(const FileEntry& a, const FileEntry& b) {
    return a.name == b.name && a.kind == b.kind && a.size == b.size && a.mtime_ms == b.mtime_ms &&
           a.birthtime_ms == b.birthtime_ms && a.mode == b.mode && a.attributes == b.attributes && a.nlink == b.nlink &&
           a.id == b.id && a.id.valid == b.id.valid && a.link_target == b.link_target && a.is_hidden == b.is_hidden &&
           a.link_is_directory == b.link_is_directory;
}

bool ModelView::less(ItemKey ka, ItemKey kb) const {
    const FileEntry& a = recs_.at(ka).item.entry;
    const FileEntry& b = recs_.at(kb).item.entry;
    if (sort_.directories_first) {
        bool da = dir_like(a), db = dir_like(b);
        if (da != db) return da;
    }
    int c = 0;
    switch (sort_.field) {
        case SortField::Name: break;
        case SortField::Size: // a directory's own size means nothing: it sorts as 0
            c = cmp(dir_like(a) ? 0 : a.size, dir_like(b) ? 0 : b.size);
            break;
        case SortField::Modified: c = cmp(a.mtime_ms, b.mtime_ms); break;
        case SortField::Type: c = natural_compare(extension(a.name), extension(b.name)); break;
        case SortField::Kind: c = cmp(static_cast<int>(a.kind), static_cast<int>(b.kind)); break;
    }
    if (c == 0) c = natural_compare(a.name, b.name);
    if (sort_.descending) c = -c;
    return c != 0 ? c < 0 : ka < kb;
}

// Would changing a's entry to b move it in the order?
bool ModelView::sort_moved(const FileEntry& a, const FileEntry& b) const {
    if (a.name != b.name || dir_like(a) != dir_like(b)) return true;
    switch (sort_.field) {
        case SortField::Name:
        case SortField::Type: return false;
        case SortField::Size: return !dir_like(a) && a.size != b.size;
        case SortField::Modified: return a.mtime_ms != b.mtime_ms;
        case SortField::Kind: return a.kind != b.kind;
    }
    return true;
}

bool ModelView::passes(const FileEntry& e) const {
    if (!show_hidden_ && e.is_hidden) return false;
    return !filter_ || filter_(e);
}

void ModelView::stage(ItemKey k) {
    if (staged_.count(k)) return;
    Staged s;
    auto it = recs_.find(k);
    if (it != recs_.end()) {
        s.had = true;
        s.was_visible = it->second.visible;
        s.old = it->second.item.entry;
    }
    staged_.emplace(k, std::move(s));
}

void ModelView::put(FileEntry e) {
    e.depth = 0;
    auto it = by_name_.find(e.name);
    if (it != by_name_.end()) {
        Rec& r = recs_.at(it->second);
        if (same_entry(r.item.entry, e)) return;
        stage(it->second);
        r.item.entry = std::move(e);
        return;
    }
    ItemKey k = next_key_++;
    stage(k);
    by_name_[e.name] = k;
    Rec r;
    r.item.key = k;
    r.item.entry = std::move(e);
    recs_.emplace(k, std::move(r));
}

void ModelView::erase(const std::string& name) {
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return;
    stage(it->second);
    recs_.erase(it->second);
    by_name_.erase(it);
}

void ModelView::rename(const std::string& from, FileEntry to) {
    auto it = by_name_.find(from);
    if (it == by_name_.end()) {
        put(std::move(to));
        return;
    }
    ItemKey k = it->second;
    if (to.name != from) erase(to.name); // whatever the rename replaced
    stage(k);
    by_name_.erase(from);
    by_name_[to.name] = k;
    to.depth = 0;
    recs_.at(k).item.entry = std::move(to);
}

void ModelView::reconcile(std::vector<FileEntry> listing) {
    std::unordered_set<std::string> present;
    for (auto& e : listing) present.insert(e.name);
    // Names that vanished, by identity, so a renamed entry keeps its key.
    std::vector<std::pair<FileId, std::string>> missing;
    for (auto& [name, k] : by_name_) {
        if (!present.count(name)) missing.emplace_back(recs_.at(k).item.entry.id, name);
    }
    std::vector<FileEntry> fresh;
    for (auto& e : listing) {
        if (by_name_.count(e.name)) {
            put(std::move(e));
        } else {
            fresh.push_back(std::move(e));
        }
    }
    for (auto& e : fresh) {
        auto m = std::find_if(missing.begin(), missing.end(), [&](const auto& p) { return p.first == e.id; });
        if (m != missing.end()) {
            std::string from = m->second;
            missing.erase(m);
            rename(from, std::move(e));
        } else {
            put(std::move(e));
        }
    }
    for (auto& [id, name] : missing) erase(name);
}

void ModelView::clear() {
    std::vector<std::string> names;
    for (auto& [name, k] : by_name_) names.push_back(name);
    for (auto& n : names) erase(n);
}

void ModelView::set_sort(SortSpec sort) {
    sort_ = sort;
    std::sort(visible_.begin(), visible_.end(), [&](ItemKey a, ItemKey b) { return less(a, b); });
}

void ModelView::set_filter(EntryFilter filter, bool show_hidden) {
    filter_ = std::move(filter);
    show_hidden_ = show_hidden;
    for (auto& [k, r] : recs_) {
        if (passes(r.item.entry) != r.visible) stage(k);
    }
}

bool ModelView::commit(std::vector<ModelOp>& ops) {
    if (staged_.empty()) return false;
    std::unordered_map<ItemKey, size_t> index;
    index.reserve(visible_.size());
    for (size_t i = 0; i < visible_.size(); ++i) index[visible_[i]] = i;

    std::vector<std::pair<size_t, ModelItem>> removals; // (old index, old item)
    std::vector<ItemKey> inserts, updates;
    for (auto& [k, s] : staged_) {
        auto it = recs_.find(k);
        const bool exists = it != recs_.end();
        const bool now_visible = exists && passes(it->second.item.entry);
        if (exists) it->second.visible = now_visible;
        if (s.was_visible) {
            ModelItem old{k, s.old};
            if (!now_visible) {
                removals.emplace_back(index.at(k), std::move(old));
            } else if (sort_moved(s.old, it->second.item.entry)) {
                removals.emplace_back(index.at(k), std::move(old));
                inserts.push_back(k);
            } else if (!same_entry(s.old, it->second.item.entry)) {
                updates.push_back(k);
            }
        } else if (now_visible) {
            inserts.push_back(k);
        }
    }
    staged_.clear();
    if (removals.empty() && inserts.empty() && updates.empty()) return false;

    std::sort(removals.begin(), removals.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    std::vector<char> gone(visible_.size(), 0);
    for (auto& [i, item] : removals) {
        gone[i] = 1;
        ops.push_back({ModelOp::Remove, i, std::move(item)});
    }
    std::vector<ItemKey> kept;
    kept.reserve(visible_.size() - removals.size() + inserts.size());
    for (size_t i = 0; i < visible_.size(); ++i) {
        if (!gone[i]) kept.push_back(visible_[i]);
    }
    auto order = [&](ItemKey a, ItemKey b) { return less(a, b); };
    std::sort(inserts.begin(), inserts.end(), order);
    visible_.clear();
    std::merge(kept.begin(), kept.end(), inserts.begin(), inserts.end(), std::back_inserter(visible_), order);
    // Insert ops in ascending final position: each index is valid when applied in order.
    std::unordered_set<ItemKey> inserted(inserts.begin(), inserts.end());
    for (size_t i = 0; i < visible_.size() && !inserted.empty(); ++i) {
        if (inserted.erase(visible_[i])) ops.push_back({ModelOp::Insert, i, recs_.at(visible_[i]).item});
    }
    for (ItemKey k : updates) {
        auto pos = std::lower_bound(visible_.begin(), visible_.end(), k, order);
        ops.push_back({ModelOp::Update, static_cast<size_t>(pos - visible_.begin()), recs_.at(k).item});
    }
    return true;
}

std::vector<ModelItem> ModelView::visible_items() const {
    std::vector<ModelItem> out;
    out.reserve(visible_.size());
    for (ItemKey k : visible_) out.push_back(recs_.at(k).item);
    return out;
}

const ModelItem* ModelView::find(ItemKey key) const {
    auto it = recs_.find(key);
    return it == recs_.end() ? nullptr : &it->second.item;
}

const ModelItem* ModelView::find_name(const std::string& name) const {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : find(it->second);
}

} // namespace bro::vfs::detail
