#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace hook_engine {

    // A single /proc/self/maps entry.
    struct MapInfo {
        uintptr_t start = 0;
        uintptr_t end = 0;
        uintptr_t offset = 0;
        dev_t dev = 0;
        ino_t inode = 0;
        int perms = 0;
        bool is_private = false;
        std::string path;

        static std::vector<MapInfo> Scan();
    };

    // Relocation-based (PLT/GOT) hook. RegisterHook only records the request;
    // CommitHook resolves the symbol table and patches every matching relocation
    // slot. Passing the original function as `fn` restores the slot.
    bool RegisterHook(dev_t dev, ino_t inode, const char *symbol, void *fn, void **backup);

    bool CommitHook();

    // Convenience wrapper used by the Zygisk Next module API, which works with a
    // library base address instead of a (dev, inode) pair.
    bool HookBase(void *base_addr, const char *symbol, void *fn, void **backup);

    // arm64 inline hook. The first 16 bytes of `target` are replaced by a jump
    // to a trampoline containing the relocated prologue; `original` receives the
    // trampoline address. Unsupported PC-relative prologues fail cleanly.
    bool InlineHook(void *target, void *replace, void **original);

    bool InlineUnhook(void *target);

    // Minimal in-memory ELF symbol resolver used by the Zygisk Next API.
    class ElfImage {
    public:
        bool Open(const char *path, void *base_addr);

        void *base() const { return reinterpret_cast<void *>(base_); }

        void *Lookup(const char *name, bool prefix, size_t *size);

        void ForEach(bool (*callback)(const char *, void *, size_t, void *), void *data);

    private:
        bool Parse();

        const char *SymbolName(size_t index) const;

        bool IsDefined(const void *sym) const;

        uintptr_t base_ = 0;
        std::vector<MapInfo> maps_;
        const void *ehdr_ = nullptr;
        const void *phdr_ = nullptr;
        size_t phnum_ = 0;
        const void *symtab_ = nullptr;
        const char *strtab_ = nullptr;
        size_t strsz_ = 0;
        size_t symcount_ = 0;
    };

} // namespace hook_engine
