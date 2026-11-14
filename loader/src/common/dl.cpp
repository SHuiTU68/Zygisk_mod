#include <dlfcn.h>
#include <android/dlext.h>

#include "dl.h"
#include "logging.h"

void* DlopenMem(int fd, int flags) {
    auto info = android_dlextinfo{
        .flags = ANDROID_DLEXT_USE_LIBRARY_FD,
        .library_fd = fd
    };

    auto* handle = android_dlopen_ext("/jit-cache", flags, &info);
    if (handle) {
        LOGV("dlopen fd %d: %p", fd, handle);
    } else {
        LOGE("dlopen fd %d: %s", fd, dlerror());
    }
    return handle;
}
