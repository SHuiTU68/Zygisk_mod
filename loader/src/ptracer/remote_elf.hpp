#pragma once

#include <cstdint>
#include <vector>

#include "utils.hpp"

struct RemoteElfInfo {
    uintptr_t base = 0;
    uintptr_t entry = 0;
};

// Maps and links an ET_DYN aarch64 library into the target process without
// going through the system linker, so the library never appears in soinfo or
// dl_iterate_phdr(). Returns false when the image uses a feature the loader
// does not implement (TLS, packed relocations, unsupported relocations); the
// caller must then fall back to the regular remote dlopen path.
bool remote_elf_load(int pid, struct user_regs_struct &regs,
                     std::vector<MapInfo> &local_map,
                     std::vector<MapInfo> &remote_map,
                     uintptr_t return_addr,
                     const char *path,
                     RemoteElfInfo *info);
