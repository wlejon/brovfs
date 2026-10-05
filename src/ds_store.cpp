// .DS_Store reader. Layout (all integers big-endian; file offsets are relative to byte 4):
//   header   00000001 "Bud1" root_offset root_size root_offset ...
//   root     block_count, unknown, block_count addresses (padded to a multiple of 256),
//            table of contents (count, then u8 length + name + u32 block id; "DSDB"),
//            free lists
//   address  offset | log2(size) in the low 5 bits
//   DSDB     root node id, levels, record count, node count, page size
//   node     P, count; P == 0: count records (leaf); else count (child id, record) pairs and
//            P is the rightmost child
//   record   u32 name length (UTF-16 units), UTF-16BE name, code[4], type[4], value
//            bool 1, long/shor/type 4, comp/dutc 8, blob u32 + bytes, ustr u32 units + UTF-16BE
#include "src/ds_store.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <iterator>

namespace bro::vfs::detail {

namespace {

class Reader {
public:
    Reader(const std::vector<unsigned char>& d, size_t begin, size_t end) : d_(d), pos_(begin), end_(end) {}
    bool u8(uint8_t& v) {
        if (pos_ + 1 > end_) return false;
        v = d_[pos_++];
        return true;
    }
    bool u32(uint32_t& v) {
        if (pos_ + 4 > end_) return false;
        v = (uint32_t(d_[pos_]) << 24) | (uint32_t(d_[pos_ + 1]) << 16) | (uint32_t(d_[pos_ + 2]) << 8) | d_[pos_ + 3];
        pos_ += 4;
        return true;
    }
    bool bytes(size_t n, std::string& out) {
        if (n > end_ - pos_) return false;
        out.assign(reinterpret_cast<const char*>(d_.data() + pos_), n);
        pos_ += n;
        return true;
    }
    bool skip(size_t n) {
        if (n > end_ - pos_) return false;
        pos_ += n;
        return true;
    }
    // `units` UTF-16BE code units as UTF-8 (unpaired surrogates become U+FFFD).
    bool utf16(size_t units, std::string& out) {
        if (units > (end_ - pos_) / 2) return false;
        out.clear();
        for (size_t i = 0; i < units; ++i) {
            uint32_t c = (uint32_t(d_[pos_]) << 8) | d_[pos_ + 1];
            pos_ += 2;
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < units) {
                uint32_t lo = (uint32_t(d_[pos_]) << 8) | d_[pos_ + 1];
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    pos_ += 2;
                    ++i;
                    c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                } else {
                    c = 0xFFFD;
                }
            } else if (c >= 0xD800 && c <= 0xDFFF) {
                c = 0xFFFD;
            }
            put_utf8(c, out);
        }
        return true;
    }

private:
    static void put_utf8(uint32_t c, std::string& out) {
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }

    const std::vector<unsigned char>& d_;
    size_t pos_;
    size_t end_;
};

class Store {
public:
    explicit Store(const std::vector<unsigned char>& d) : d_(d) {}

    bool parse(std::vector<DsRecord>& out) {
        if (d_.size() < 36) return false;
        Reader h(d_, 0, d_.size());
        uint32_t magic = 0, root_off = 0, root_size = 0, root_off2 = 0;
        std::string bud;
        if (!h.u32(magic) || !h.bytes(4, bud) || !h.u32(root_off) || !h.u32(root_size) || !h.u32(root_off2)) return false;
        if (magic != 1 || bud != "Bud1" || root_off != root_off2) return false;
        if (size_t(root_off) + 4 + root_size > d_.size()) return false;
        Reader r(d_, size_t(root_off) + 4, size_t(root_off) + 4 + root_size);
        uint32_t nblocks = 0, unknown = 0;
        if (!r.u32(nblocks) || !r.u32(unknown) || nblocks > 1u << 20) return false;
        addrs_.resize(nblocks);
        for (auto& a : addrs_) {
            if (!r.u32(a)) return false;
        }
        if (!r.skip(size_t((256 - nblocks % 256) % 256) * 4)) return false;
        uint32_t ntoc = 0;
        if (!r.u32(ntoc) || ntoc > 1024) return false;
        uint32_t dsdb = UINT32_MAX;
        for (uint32_t i = 0; i < ntoc; ++i) {
            uint8_t len = 0;
            std::string name;
            uint32_t id = 0;
            if (!r.u8(len) || !r.bytes(len, name) || !r.u32(id)) return false;
            if (name == "DSDB") dsdb = id;
        }
        if (dsdb == UINT32_MAX) return false;
        size_t b = 0, e = 0;
        if (!block(dsdb, b, e)) return false;
        Reader db(d_, b, e);
        uint32_t root = 0, levels = 0;
        if (!db.u32(root) || !db.u32(levels) || levels > 32) return false;
        return node(root, 0, out);
    }

private:
    bool block(uint32_t id, size_t& begin, size_t& end) const {
        if (id >= addrs_.size()) return false;
        uint32_t a = addrs_[id];
        uint32_t shift = a & 0x1F;
        if (shift < 5 || shift > 30) return false;
        begin = size_t(a & ~0x1Fu) + 4;
        if (begin >= d_.size()) return false;
        end = std::min(begin + (size_t(1) << shift), d_.size()); // a final block may be cut short
        return true;
    }

    bool record(Reader& r, std::vector<DsRecord>& out) {
        DsRecord rec;
        uint32_t nlen = 0;
        if (!r.u32(nlen) || !r.utf16(nlen, rec.item) || !r.bytes(4, rec.code) || !r.bytes(4, rec.type)) return false;
        uint32_t len = 0;
        if (rec.type == "bool") {
            if (!r.skip(1)) return false;
        } else if (rec.type == "long" || rec.type == "shor" || rec.type == "type") {
            if (!r.skip(4)) return false;
        } else if (rec.type == "comp" || rec.type == "dutc") {
            if (!r.skip(8)) return false;
        } else if (rec.type == "blob") {
            if (!r.u32(len) || !r.skip(len)) return false;
        } else if (rec.type == "ustr") {
            if (!r.u32(len) || !r.utf16(len, rec.text)) return false;
        } else {
            return false; // unknown type: the record's length is unknown, so is everything after it
        }
        out.push_back(std::move(rec));
        return true;
    }

    bool node(uint32_t id, int depth, std::vector<DsRecord>& out) {
        if (depth > 32) return false;
        size_t b = 0, e = 0;
        if (!block(id, b, e)) return false;
        Reader r(d_, b, e);
        uint32_t p = 0, count = 0;
        if (!r.u32(p) || !r.u32(count)) return false;
        for (uint32_t i = 0; i < count; ++i) {
            if (p != 0) {
                uint32_t child = 0;
                if (!r.u32(child) || !node(child, depth + 1, out)) return false;
            }
            if (!record(r, out)) return false;
        }
        return p == 0 || node(p, depth + 1, out);
    }

    const std::vector<unsigned char>& d_;
    std::vector<uint32_t> addrs_;
};

} // namespace

bool read_ds_store(const std::vector<unsigned char>& data, std::vector<DsRecord>& out, std::error_code& ec) {
    out.clear();
    Store s(data);
    if (!s.parse(out)) {
        out.clear();
        ec = std::make_error_code(std::errc::illegal_byte_sequence);
        return false;
    }
    return true;
}

bool read_finder_putback(const std::filesystem::path& ds_store, std::map<std::string, FinderPutBack>& out,
                         std::error_code& ec) {
    out.clear();
    std::ifstream in(ds_store, std::ios::binary);
    if (!in) {
        ec = std::error_code(errno ? errno : ENOENT, std::generic_category());
        return false;
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) {
        ec = std::make_error_code(std::errc::io_error);
        return false;
    }
    std::vector<DsRecord> recs;
    if (!read_ds_store(data, recs, ec)) return false;
    for (auto& r : recs) {
        if (r.type != "ustr") continue;
        if (r.code == "ptbL") out[r.item].location = std::move(r.text);
        if (r.code == "ptbN") out[r.item].name = std::move(r.text);
    }
    // A name without a location is not a put-back record.
    for (auto it = out.begin(); it != out.end();) {
        it = it->second.location.empty() ? out.erase(it) : std::next(it);
    }
    return true;
}

} // namespace bro::vfs::detail
