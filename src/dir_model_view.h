#pragma once
// The pure half of DirectoryModel: items by key and by name, the sorted visible list, and the
// diff between two states of it. No I/O, no threads (dir_model.cpp drives it).

#include "brovfs/dir_model.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace bro::vfs::detail {

class ModelView {
public:
    explicit ModelView(SortSpec sort = SortSpec(), bool show_hidden = false, EntryFilter filter = nullptr)
        : sort_(sort), show_hidden_(show_hidden), filter_(std::move(filter)) {}

    // Staged changes, turned into ops by commit().
    void put(FileEntry e);                                   // insert or update by name
    void erase(const std::string& name);
    void rename(const std::string& from, FileEntry to);      // keeps the key
    // A complete listing: updates what changed, erases what is missing, and keeps the key of
    // an entry that reappears under another name with the same identity (a rename).
    void reconcile(std::vector<FileEntry> listing);
    void clear();                                            // every entry erased

    void set_sort(SortSpec sort);                            // re-sorts; take a reset after
    void set_filter(EntryFilter filter, bool show_hidden);   // stages visibility changes

    // Applies the staged changes to the visible list and appends the ops (see ModelOp).
    // Returns true if anything visible changed.
    bool commit(std::vector<ModelOp>& ops);

    [[nodiscard]] std::vector<ModelItem> visible_items() const;
    [[nodiscard]] const ModelItem* find(ItemKey key) const;
    [[nodiscard]] const ModelItem* find_name(const std::string& name) const;
    [[nodiscard]] size_t size() const noexcept { return recs_.size(); }
    [[nodiscard]] bool less(ItemKey a, ItemKey b) const; // the visible order

private:
    struct Rec {
        ModelItem item;
        bool visible = false;
    };
    struct Staged {
        bool had = false; // existed before this commit
        bool was_visible = false;
        FileEntry old;
    };

    bool passes(const FileEntry& e) const;
    void stage(ItemKey k);
    bool sort_moved(const FileEntry& a, const FileEntry& b) const;

    SortSpec sort_;
    bool show_hidden_;
    EntryFilter filter_;
    ItemKey next_key_ = 1;
    std::unordered_map<ItemKey, Rec> recs_;
    std::unordered_map<std::string, ItemKey> by_name_;
    std::vector<ItemKey> visible_; // sorted by less()
    std::unordered_map<ItemKey, Staged> staged_;
};

bool same_entry(const FileEntry& a, const FileEntry& b);

} // namespace bro::vfs::detail
