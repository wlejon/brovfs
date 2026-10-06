// Test executables never open a modal dialog: a Debug CRT assert, abort() or
// crash would otherwise block CI and the developer's desktop until clicked.
// Asserts and CRT errors print to stderr and end the process (exit 3), so a
// failure fails the test instead of looping or waiting. Linked into every
// test executable; the static object runs before main().
#ifdef _WIN32
#include <windows.h>
#include <crtdbg.h>
#include <cstdio>
#include <cstdlib>

namespace {
int __cdecl reportToStderr(int type, char* message, int* returnValue) {
    std::fputs(message, stderr);
    if (type != _CRT_WARN) {
        std::fflush(stderr);
        std::_Exit(3);
    }
    *returnValue = 0;
    return TRUE;
}

struct NoDialogs {
    NoDialogs() {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
        _CrtSetReportHook2(_CRT_RPTHOOK_INSTALL, reportToStderr);
    }
};
const NoDialogs kNoDialogs;
}  // namespace
#endif
