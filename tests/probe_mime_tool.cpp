// Reads UTF-8 paths from stdin, prints "<sniffed-mime>\t<path>" per line. Used to diff against `file --mime-type`.
// Not a ctest: e.g. `find dir -type f | probe_mime_tool` vs `file --mime-type -f -`.
#include "brovfs/mime.h"
#include "brovfs/path.h"
#include <iostream>
#include <string>

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::cout << bro::vfs::sniff_mime_type_from_file(bro::vfs::path_from_utf8(line)) << "\t" << line << "\n";
    }
    return 0;
}
