#pragma once
// "What type is this file": content sniffing, name patterns and the platform's type database.
//
// brovfs is the one owner of file-type detection in the desktop substrate. Associations (which
// application opens a type) belong to broapps; thumbnail extractor choice to brothumb; both ask
// here for the type.
//
// Two layers:
//  * sniff_mime_type*: magic-byte signatures, identical on every machine.
//  * MimeDatabase: name -> type (literal names, extensions, glob patterns), type -> extensions,
//    aliases and the subclass relation, plus type_for_file / type_for_data which reconcile the
//    name with the content. MimeDatabase::system() is the platform's database: shared-mime-info
//    on Linux (globs2 / aliases / subclasses from the XDG data dirs), UTType on macOS, the
//    registry's Content Type (AssocQueryString) on Windows. Each falls back to the built-in table
//    for anything it does not answer. MimeDatabase::built_in() is that table alone: the same
//    answers everywhere, the deterministic oracle for tests.
//
// Type names are lower case. Each database reports its own canonical spelling (canonical());
// sniffed types are passed through it, so a name answer and a content answer for one file
// compare equal.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace bro::vfs {

// Sniff a MIME type from magic bytes (the first 512 bytes are enough for every signature).
// Text that matches no signature is "text/plain"; binary is "application/octet-stream".
[[nodiscard]] std::string sniff_mime_type(std::span<const uint8_t> buffer);

// Read up to max_read_bytes from the file and sniff. Unreadable -> "application/octet-stream",
// empty -> "application/x-empty".
[[nodiscard]] std::string sniff_mime_type_from_file(const std::filesystem::path& path, size_t max_read_bytes = 512);

// "image", "audio", "video", "font", "model", "document", "archive", "executable", "code",
// "text" or "binary".
[[nodiscard]] std::string get_mime_category(std::string_view mime_type);

// Built-in table shorthands (MimeDatabase::built_in()): extension (with or without leading dot,
// case-insensitive) -> MIME, unknown -> "application/octet-stream"; MIME -> preferred extension
// without dot, unknown -> "bin".
[[nodiscard]] std::string extension_to_mime(std::string_view ext);
[[nodiscard]] std::string mime_to_extension(std::string_view mime_type);

// NUL bytes or a low printable ratio in the first 512 bytes.
[[nodiscard]] bool is_binary_buffer(std::span<const uint8_t> buffer);

// What a file's type was decided from.
enum class TypeBasis : uint8_t {
    None,     // neither name nor content said anything: application/octet-stream
    Name,     // the name alone (content unreadable, missing, empty or uninformative)
    Content,  // the content alone (no name match, or a signature that contradicts the name)
    Both,     // name and content agree (or the name is a more specific kind of the content)
};

struct FileType {
    std::string mime;        // the answer
    std::string by_name;     // what the name says ("" when it says nothing)
    std::string by_content;  // what the content says ("" when not read)
    TypeBasis basis = TypeBasis::None;
};

class MimeDatabase {
public:
    virtual ~MimeDatabase() = default;

    // The platform's database, loaded once on first use; thread-safe and immutable.
    [[nodiscard]] static const MimeDatabase& system();
    // The built-in table alone.
    [[nodiscard]] static const MimeDatabase& built_in();
    // A shared-mime-info database read from `mime_dirs` (each a ".../share/mime" directory
    // holding globs2 or globs, aliases, subclasses), highest priority first, with the built-in
    // table behind it. Works on every OS: a host can ship a private database, and tests use it.
    // Fails (ec set, null) only when no directory had a globs file.
    [[nodiscard]] static std::unique_ptr<MimeDatabase> load_shared_mime_info(
        const std::vector<std::filesystem::path>& mime_dirs, std::error_code& ec);
    // The directories MimeDatabase::system() reads on Linux: $XDG_DATA_HOME/mime then each
    // $XDG_DATA_DIRS entry + /mime (defaults applied as the XDG base-directory spec says).
    [[nodiscard]] static std::vector<std::filesystem::path> xdg_mime_dirs();

    // "built-in", "shared-mime-info", "UTType" or "Windows registry".
    [[nodiscard]] virtual std::string_view backend() const noexcept = 0;

    // Every type the name matches, best first (literal names, then the highest-weight and then
    // longest pattern: "*.tar.gz" before "*.gz"). Empty when the name says nothing.
    [[nodiscard]] virtual std::vector<std::string> types_for_name(std::string_view file_name) const = 0;
    // types_for_name's first answer, or "" when there is none.
    [[nodiscard]] std::string type_for_name(std::string_view file_name) const;
    // Extension with or without its dot; "application/octet-stream" when unknown.
    [[nodiscard]] std::string type_for_extension(std::string_view ext) const;

    // Extensions (no dot) a type is saved with, preferred first; empty when unknown.
    [[nodiscard]] virtual std::vector<std::string> extensions_for_type(std::string_view mime) const = 0;

    // Alias -> this database's canonical name; lower-cased; unknown names come back unchanged.
    [[nodiscard]] virtual std::string canonical(std::string_view mime) const = 0;

    // True when `mime` is `ancestor` or a subclass of it, through declared parents and the
    // implicit rules: text/* is text/plain; "+xml" / "+json" / "+zip" types are application/xml /
    // json / zip; everything but inode/* is application/octet-stream.
    [[nodiscard]] virtual bool is_a(std::string_view mime, std::string_view ancestor) const = 0;

    // Type of an on-disk object from its name and its first bytes. A directory is
    // "inode/directory"; a missing or unreadable file is typed by name alone.
    //
    // The name wins when the content is uninformative (empty, unrecognised binary, plain text
    // whose name is a text type) or when the name is a more specific kind of the content (a
    // .docx is a zip, a .svg is XML, a .cpp is text); a recognised signature beats a name that
    // contradicts it (a PNG called notes.txt is image/png); text named as a binary format is
    // text/plain.
    [[nodiscard]] FileType type_for_file(const std::filesystem::path& path) const;
    // The same decision for a name and bytes already in hand (`head` empty and `have_content`
    // true means an empty file).
    [[nodiscard]] FileType type_for_data(std::string_view file_name, std::span<const uint8_t> head,
                                         bool have_content = true) const;
};

} // namespace bro::vfs
