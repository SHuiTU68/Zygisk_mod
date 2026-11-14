#include "remote_elf.hpp"

#if !defined(__aarch64__)

bool remote_elf_load(int, struct user_regs_struct &, std::vector<MapInfo> &,
                     std::vector<MapInfo> &, uintptr_t, const char *, RemoteElfInfo *) {
    return false;
}

#else

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <string>

#include "logging.h"

#ifndef ElfW
#define ElfW(type) Elf64_##type
#endif

#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
#ifndef DT_ANDROID_REL
#define DT_ANDROID_REL 0x6000000f
#endif
#ifndef DT_ANDROID_RELSZ
#define DT_ANDROID_RELSZ 0x60000010
#endif
#ifndef DT_ANDROID_RELA
#define DT_ANDROID_RELA 0x60000011
#endif
#ifndef DT_ANDROID_RELASZ
#define DT_ANDROID_RELASZ 0x60000012
#endif

namespace {

constexpr uintptr_t kRemoteFailed = static_cast<uintptr_t>(-1);
constexpr size_t kMaxSymbols = 1u << 20;

struct Image {
    std::vector<uint8_t> data;
    const ElfW(Ehdr) *eh = nullptr;
    const ElfW(Phdr) *ph = nullptr;
    size_t phnum = 0;
};

struct DynamicInfo {
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    uintptr_t strsz = 0;
    uintptr_t rela = 0;
    uintptr_t relasz = 0;
    uintptr_t jmprel = 0;
    uintptr_t pltrelsz = 0;
    uintptr_t pltrel = 0;
    uintptr_t init = 0;
    uintptr_t init_array = 0;
    uintptr_t init_arraysz = 0;
    uintptr_t hash = 0;
    uintptr_t gnu_hash = 0;
    uintptr_t relr = 0;
    uintptr_t relrsz = 0;
    std::vector<std::string> needed;
};

uintptr_t page_size() {
    static const uintptr_t value = [] {
        long page = sysconf(_SC_PAGESIZE);
        return page > 0 ? static_cast<uintptr_t>(page) : 4096u;
    }();
    return value;
}

uintptr_t align_down(uintptr_t value) {
    return value & ~(page_size() - 1);
}

uintptr_t align_up(uintptr_t value) {
    return (value + page_size() - 1) & ~(page_size() - 1);
}

bool load_image(const char *path, Image *img) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        PLOGE("open %s", path);
        return false;
    }
    struct stat st {};
    if (fstat(fd, &st) == -1 || st.st_size < static_cast<off_t>(sizeof(ElfW(Ehdr)))) {
        PLOGE("fstat %s", path);
        close(fd);
        return false;
    }
    img->data.resize(static_cast<size_t>(st.st_size));
    size_t done = 0;
    while (done < img->data.size()) {
        ssize_t n = read(fd, img->data.data() + done, img->data.size() - done);
        if (n <= 0) {
            PLOGE("read %s", path);
            close(fd);
            return false;
        }
        done += static_cast<size_t>(n);
    }
    close(fd);

    if (img->data.size() < sizeof(ElfW(Ehdr))) return false;
    img->eh = reinterpret_cast<const ElfW(Ehdr) *>(img->data.data());
    if (memcmp(img->eh->e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (img->eh->e_ident[EI_CLASS] != ELFCLASS64) return false;
    if (img->eh->e_machine != EM_AARCH64) return false;
    if (img->eh->e_type != ET_DYN) return false;
    if (img->eh->e_phentsize != sizeof(ElfW(Phdr))) return false;
    if (img->eh->e_phnum == 0) return false;
    size_t ph_size = static_cast<size_t>(img->eh->e_phnum) * sizeof(ElfW(Phdr));
    if (img->eh->e_phoff > img->data.size() || ph_size > img->data.size() - img->eh->e_phoff) {
        return false;
    }
    img->ph = reinterpret_cast<const ElfW(Phdr) *>(img->data.data() + img->eh->e_phoff);
    img->phnum = img->eh->e_phnum;
    return true;
}

bool vaddr_to_offset(const Image &img, uintptr_t vaddr, size_t *offset) {
    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        if (ph.p_type != PT_LOAD) continue;
        if (vaddr < ph.p_vaddr || vaddr - ph.p_vaddr >= ph.p_filesz) continue;
        uintptr_t off = ph.p_offset + (vaddr - ph.p_vaddr);
        if (off >= img.data.size()) return false;
        *offset = static_cast<size_t>(off);
        return true;
    }
    return false;
}

uintptr_t read_uptr_at(const Image &img, uintptr_t vaddr, bool *ok) {
    size_t offset = 0;
    if (!vaddr_to_offset(img, vaddr, &offset) || offset + sizeof(uintptr_t) > img.data.size()) {
        *ok = false;
        return 0;
    }
    uintptr_t value = 0;
    memcpy(&value, img.data.data() + offset, sizeof(value));
    return value;
}

uint32_t read_u32(const uint8_t *p) {
    uint32_t value = 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

bool parse_dynamic(const Image &img, const ElfW(Phdr) &ph, DynamicInfo *out) {
    size_t offset = 0;
    if (!vaddr_to_offset(img, ph.p_vaddr, &offset)) return false;
    if (ph.p_filesz == 0 || offset + ph.p_filesz > img.data.size()) return false;
    auto *dyn = reinterpret_cast<const ElfW(Dyn) *>(img.data.data() + offset);
    size_t count = ph.p_filesz / sizeof(ElfW(Dyn));
    std::vector<uintptr_t> needed_offsets;
    bool done = false;
    for (size_t i = 0; i < count && !done; ++i) {
        switch (dyn[i].d_tag) {
            case DT_NULL:
                done = true;
                break;
            case DT_NEEDED:
                needed_offsets.push_back(dyn[i].d_un.d_val);
                break;
            case DT_STRTAB:
                out->strtab = dyn[i].d_un.d_ptr;
                break;
            case DT_STRSZ:
                out->strsz = dyn[i].d_un.d_val;
                break;
            case DT_SYMTAB:
                out->symtab = dyn[i].d_un.d_ptr;
                break;
            case DT_RELA:
                out->rela = dyn[i].d_un.d_ptr;
                break;
            case DT_RELASZ:
                out->relasz = dyn[i].d_un.d_val;
                break;
            case DT_JMPREL:
                out->jmprel = dyn[i].d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                out->pltrelsz = dyn[i].d_un.d_val;
                break;
            case DT_PLTREL:
                out->pltrel = dyn[i].d_un.d_val;
                break;
            case DT_INIT:
                out->init = dyn[i].d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                out->init_array = dyn[i].d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                out->init_arraysz = dyn[i].d_un.d_val;
                break;
            case DT_HASH:
                out->hash = dyn[i].d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                out->gnu_hash = dyn[i].d_un.d_ptr;
                break;
            case DT_RELR:
                out->relr = dyn[i].d_un.d_ptr;
                break;
            case DT_RELRSZ:
                out->relrsz = dyn[i].d_un.d_val;
                break;
            case DT_ANDROID_REL:
            case DT_ANDROID_RELA:
                LOGD("remote loader: Android packed relocations are not supported");
                return false;
            default:
                break;
        }
    }
    if (out->strtab == 0 || out->strsz == 0) return false;
    for (uintptr_t needed : needed_offsets) {
        if (needed >= out->strsz) return false;
        size_t str_offset = 0;
        if (!vaddr_to_offset(img, out->strtab + needed, &str_offset)) return false;
        const char *name = reinterpret_cast<const char *>(img.data.data() + str_offset);
        size_t remain = std::min<size_t>(out->strsz - needed, img.data.size() - str_offset);
        if (memchr(name, '\0', remain) == nullptr) return false;
        out->needed.emplace_back(name);
    }
    return true;
}

size_t dynsym_count(const Image &img, const DynamicInfo &dyn) {
    if (dyn.hash != 0) {
        size_t offset = 0;
        if (vaddr_to_offset(img, dyn.hash, &offset) && offset + 8 <= img.data.size()) {
            uint32_t nchain = read_u32(img.data.data() + offset + 4);
            if (nchain != 0 && nchain <= kMaxSymbols) return nchain;
        }
    }
    if (dyn.gnu_hash != 0) {
        size_t offset = 0;
        if (!vaddr_to_offset(img, dyn.gnu_hash, &offset)) return 0;
        const uint8_t *base = img.data.data() + offset;
        size_t avail = img.data.size() - offset;
        if (avail < 16) return 0;
        uint32_t nbuckets = read_u32(base);
        uint32_t symoffset = read_u32(base + 4);
        uint32_t bloom_size = read_u32(base + 8);
        if (nbuckets == 0 || bloom_size > (avail - 16) / 8) return 0;
        size_t buckets_offset = 16 + static_cast<size_t>(bloom_size) * 8;
        if (buckets_offset + static_cast<size_t>(nbuckets) * 4 > avail) return 0;
        auto *buckets = reinterpret_cast<const uint32_t *>(base + buckets_offset);
        auto *chains = buckets + nbuckets;
        const uint8_t *end = img.data.data() + img.data.size();
        size_t max_sym = symoffset;
        for (uint32_t i = 0; i < nbuckets; ++i) {
            uint32_t bucket = buckets[i];
            if (bucket < symoffset) continue;
            size_t index = bucket;
            while (true) {
                size_t chain_index = index - symoffset;
                if (reinterpret_cast<const uint8_t *>(chains + chain_index) + 4 > end) return 0;
                if ((chains[chain_index] & 1u) != 0) break;
                if (++index - symoffset > kMaxSymbols) return 0;
            }
            max_sym = std::max(max_sym, index + 1);
        }
        if (max_sym > 0 && max_sym <= kMaxSymbols) return max_sym;
    }
    if (dyn.strtab > dyn.symtab) {
        size_t count = (dyn.strtab - dyn.symtab) / sizeof(ElfW(Sym));
        if (count != 0 && count <= kMaxSymbols) return count;
    }
    return 0;
}

class Remote {
public:
    Remote(int pid, struct user_regs_struct &regs, std::vector<MapInfo> &local,
           std::vector<MapInfo> &remote, uintptr_t return_addr)
            : pid_(pid), regs_(regs), local_(local), remote_(remote), return_addr_(return_addr) {}

    uintptr_t call(const char *lib, const char *name, const std::vector<long> &args) {
        std::string key = std::string(lib) + ':' + name;
        auto it = funcs_.find(key);
        uintptr_t address = 0;
        if (it != funcs_.end()) {
            address = it->second;
        } else {
            address = reinterpret_cast<uintptr_t>(find_func_addr(local_, remote_, lib, name));
            funcs_[key] = address;
        }
        if (address == 0) return kRemoteFailed;
        std::vector<long> argv = args;
        return remote_call(pid_, regs_, address, return_addr_, argv);
    }

    uintptr_t mmap(uintptr_t addr, size_t length, int prot, int flags, int fd, off_t offset) {
        return call("libc.so", "mmap",
                    {static_cast<long>(addr), static_cast<long>(length), prot, flags, fd,
                     static_cast<long>(offset)});
    }

    uintptr_t munmap(uintptr_t addr, size_t length) {
        return call("libc.so", "munmap", {static_cast<long>(addr), static_cast<long>(length)});
    }

    bool mprotect(uintptr_t addr, size_t length, int prot) {
        return call("libc.so", "mprotect",
                    {static_cast<long>(addr), static_cast<long>(length), prot}) != kRemoteFailed;
    }

private:
    int pid_;
    struct user_regs_struct &regs_;
    std::vector<MapInfo> &local_;
    std::vector<MapInfo> &remote_;
    uintptr_t return_addr_;
    std::map<std::string, uintptr_t> funcs_;
};

class SymbolResolver {
public:
    SymbolResolver(std::vector<MapInfo> &local, std::vector<MapInfo> &remote,
                   const std::vector<std::string> &needed)
            : local_(local), remote_(remote), needed_(needed) {}

    uintptr_t find(const char *name) {
        for (const auto &lib : needed_) {
            if (uintptr_t address = find_in(lib, name)) return address;
        }
        static const char *const kFallback[] = {
                "libc.so", "liblog.so", "libm.so", "libdl.so",
                "libc++_shared.so", "libstdc++.so"
        };
        for (const char *lib : kFallback) {
            if (uintptr_t address = find_in(lib, name)) return address;
        }
        return 0;
    }

private:
    uintptr_t find_in(const std::string &lib, const char *name) {
        void *&handle = handles_[lib];
        if (handle == nullptr) {
            handle = dlopen(lib.c_str(), RTLD_NOW);
            if (handle == nullptr) return 0;
        }
        void *symbol = dlsym(handle, name);
        if (symbol == nullptr) return 0;
        uintptr_t local_base = reinterpret_cast<uintptr_t>(find_module_base(local_, lib));
        uintptr_t remote_base = reinterpret_cast<uintptr_t>(find_module_base(remote_, lib));
        if (local_base == 0 || remote_base == 0) return 0;
        return reinterpret_cast<uintptr_t>(symbol) - local_base + remote_base;
    }

    std::vector<MapInfo> &local_;
    std::vector<MapInfo> &remote_;
    const std::vector<std::string> &needed_;
    std::map<std::string, void *> handles_;
};

} // namespace

bool remote_elf_load(int pid, struct user_regs_struct &regs,
                     std::vector<MapInfo> &local_map,
                     std::vector<MapInfo> &remote_map,
                     uintptr_t return_addr,
                     const char *path,
                     RemoteElfInfo *info) {
    if (info == nullptr || path == nullptr) return false;
    Image img;
    if (!load_image(path, &img)) return false;

    const ElfW(Phdr) *dynamic_phdr = nullptr;
    const ElfW(Phdr) *relro_phdr = nullptr;
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    bool has_tls = false;
    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        switch (ph.p_type) {
            case PT_LOAD:
                if (ph.p_memsz == 0) break;
                min_vaddr = std::min(min_vaddr, static_cast<uintptr_t>(ph.p_vaddr));
                max_vaddr = std::max(max_vaddr,
                                     static_cast<uintptr_t>(ph.p_vaddr + ph.p_memsz));
                break;
            case PT_DYNAMIC:
                dynamic_phdr = &ph;
                break;
            case PT_GNU_RELRO:
                relro_phdr = &ph;
                break;
            case PT_TLS:
                has_tls = true;
                break;
            default:
                break;
        }
    }
    if (dynamic_phdr == nullptr || min_vaddr == UINTPTR_MAX || max_vaddr <= min_vaddr) return false;
    if (has_tls) {
        LOGD("remote loader: PT_TLS is not supported, falling back to dlopen");
        return false;
    }

    DynamicInfo dyn;
    if (!parse_dynamic(img, *dynamic_phdr, &dyn)) return false;
    if (dyn.symtab == 0) return false;
    size_t symbol_count = dynsym_count(img, dyn);
    if (symbol_count == 0) return false;

    struct user_regs_struct saved_regs = regs;
    Remote remote(pid, regs, local_map, remote_map, return_addr);

    const uintptr_t start = align_down(min_vaddr);
    const uintptr_t end = align_up(max_vaddr);
    if (end <= start) return false;
    const size_t map_size = static_cast<size_t>(end - start);
    uintptr_t base = remote.mmap(0, map_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == kRemoteFailed || base == 0) {
        regs = saved_regs;
        return false;
    }
    const uintptr_t bias = base - start;

    auto fail = [&]() {
        remote.munmap(base, map_size);
        regs = saved_regs;
        return false;
    };

    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) continue;
        if (ph.p_offset > img.data.size() || ph.p_filesz > img.data.size() - ph.p_offset) {
            return fail();
        }
        if (write_proc(pid, bias + ph.p_vaddr, img.data.data() + ph.p_offset, ph.p_filesz) !=
            static_cast<ssize_t>(ph.p_filesz)) {
            return fail();
        }
    }

    // IRELATIVE and STT_GNU_IFUNC relocations call resolver code inside the
    // image, so executable segments must be executable before relocations are
    // applied. Writable segments stay RW until the final permission pass.
    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0 || (ph.p_flags & PF_X) == 0) continue;
        uintptr_t seg_start = align_down(ph.p_vaddr);
        uintptr_t seg_end = align_up(ph.p_vaddr + ph.p_memsz);
        int prot = PROT_READ | PROT_EXEC;
        if ((ph.p_flags & PF_W) != 0) prot |= PROT_WRITE;
        if (!remote.mprotect(bias + seg_start, seg_end - seg_start, prot)) return fail();
    }

    auto sym_at = [&](size_t index) -> const ElfW(Sym) * {
        size_t offset = 0;
        uintptr_t address = dyn.symtab + index * sizeof(ElfW(Sym));
        if (!vaddr_to_offset(img, address, &offset)) return nullptr;
        if (offset + sizeof(ElfW(Sym)) > img.data.size()) return nullptr;
        return reinterpret_cast<const ElfW(Sym) *>(img.data.data() + offset);
    };

    auto sym_name = [&](const ElfW(Sym) &sym) -> const char * {
        if (sym.st_name == 0 || sym.st_name >= dyn.strsz) return nullptr;
        size_t offset = 0;
        if (!vaddr_to_offset(img, dyn.strtab + sym.st_name, &offset)) return nullptr;
        if (offset >= img.data.size()) return nullptr;
        const char *name = reinterpret_cast<const char *>(img.data.data() + offset);
        size_t remain = std::min<size_t>(dyn.strsz - sym.st_name, img.data.size() - offset);
        if (memchr(name, '\0', remain) == nullptr) return nullptr;
        return name;
    };

    SymbolResolver resolver(local_map, remote_map, dyn.needed);

    auto write_value = [&](uintptr_t vaddr, uintptr_t value) {
        return write_proc(pid, bias + vaddr, &value, sizeof(value)) ==
               static_cast<ssize_t>(sizeof(value));
    };

    auto relocation_value = [&](const ElfW(Sym) *sym, unsigned type, uintptr_t addend,
                                bool *ok) -> uintptr_t {
        *ok = true;
        switch (type) {
            case R_AARCH64_RELATIVE:
                return bias + addend;
            case R_AARCH64_IRELATIVE: {
                std::vector<long> no_args;
                uintptr_t result = remote_call(pid, regs, bias + addend, return_addr, no_args);
                if (result == kRemoteFailed) *ok = false;
                return result;
            }
            default:
                break;
        }
        if (sym == nullptr) {
            // STN_UNDEF: for ABS/GLOB_DAT/JUMP_SLOT the symbol value is zero.
            return addend;
        }
        uintptr_t value = 0;
        if (sym->st_shndx != SHN_UNDEF) {
            value = bias + sym->st_value;
            if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                std::vector<long> no_args;
                value = remote_call(pid, regs, value, return_addr, no_args);
                if (value == kRemoteFailed) *ok = false;
            }
        } else {
            const char *name = sym_name(*sym);
            if (name != nullptr &&
                (strcmp(name, "__register_frame") == 0 || strcmp(name, "__deregister_frame") == 0)) {
                // The system linker normally resolves these to no-ops. We never
                // register unwind tables, so binding them to zero is intentional.
                value = 0;
            } else if (name != nullptr && *name != '\0') {
                value = resolver.find(name);
            }
            if (value == 0 && ELF64_ST_BIND(sym->st_info) != STB_WEAK) *ok = false;
        }
        return value + addend;
    };

    auto apply_rela = [&](uintptr_t vaddr, size_t size) -> bool {
        if (size == 0) return true;
        if (size % sizeof(ElfW(Rela)) != 0) return false;
        size_t offset = 0;
        if (!vaddr_to_offset(img, vaddr, &offset) || offset + size > img.data.size()) return false;
        auto *rela = reinterpret_cast<const ElfW(Rela) *>(img.data.data() + offset);
        size_t count = size / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; ++i) {
            unsigned type = ELF64_R_TYPE(rela[i].r_info);
            if (type == R_AARCH64_NONE) continue;
            if (type != R_AARCH64_ABS64 && type != R_AARCH64_GLOB_DAT &&
                type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_RELATIVE &&
                type != R_AARCH64_IRELATIVE) {
                LOGD("remote loader: unsupported relocation type %u", type);
                return false;
            }
            const ElfW(Sym) *sym = nullptr;
            if (type != R_AARCH64_RELATIVE && type != R_AARCH64_IRELATIVE) {
                size_t index = ELF64_R_SYM(rela[i].r_info);
                if (index >= symbol_count) return false;
                sym = sym_at(index);
                if (sym == nullptr) return false;
            }
            bool ok = true;
            uintptr_t value = relocation_value(sym, type,
                                               static_cast<uintptr_t>(rela[i].r_addend), &ok);
            if (!ok) {
                LOGD("remote loader: unresolved symbol for relocation %zu", i);
                return false;
            }
            if (!write_value(rela[i].r_offset, value)) return false;
        }
        return true;
    };

    if (!apply_rela(dyn.rela, dyn.relasz)) return fail();
    if (dyn.jmprel != 0) {
        if (dyn.pltrel != DT_RELA) return fail();
        if (!apply_rela(dyn.jmprel, dyn.pltrelsz)) return fail();
    }

    if (dyn.relr != 0) {
        if (dyn.relrsz == 0 || dyn.relrsz % sizeof(uintptr_t) != 0) return fail();
        size_t offset = 0;
        if (!vaddr_to_offset(img, dyn.relr, &offset) ||
            offset + dyn.relrsz > img.data.size()) {
            return fail();
        }
        auto *entries = reinterpret_cast<const uintptr_t *>(img.data.data() + offset);
        size_t count = dyn.relrsz / sizeof(uintptr_t);
        uintptr_t where = 0;
        for (size_t i = 0; i < count; ++i) {
            uintptr_t entry = entries[i];
            if ((entry & 1u) == 0) {
                where = entry;
                bool ok = true;
                uintptr_t addend = read_uptr_at(img, where, &ok);
                if (!ok || !write_value(where, bias + addend)) return fail();
                where += sizeof(uintptr_t);
            } else {
                uintptr_t bitmap = entry >> 1;
                for (size_t bit = 0; bitmap != 0; ++bit, bitmap >>= 1) {
                    if ((bitmap & 1u) == 0) continue;
                    uintptr_t target = where + bit * sizeof(uintptr_t);
                    bool ok = true;
                    uintptr_t addend = read_uptr_at(img, target, &ok);
                    if (!ok || !write_value(target, bias + addend)) return fail();
                }
                where += (sizeof(uintptr_t) * 8 - 1) * sizeof(uintptr_t);
            }
        }
    }

    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;
        uintptr_t seg_start = align_down(ph.p_vaddr);
        uintptr_t seg_end = align_up(ph.p_vaddr + ph.p_memsz);
        int prot = 0;
        if ((ph.p_flags & PF_R) != 0) prot |= PROT_READ;
        if ((ph.p_flags & PF_W) != 0) prot |= PROT_WRITE;
        if ((ph.p_flags & PF_X) != 0) prot |= PROT_EXEC;
        if (!remote.mprotect(bias + seg_start, seg_end - seg_start, prot)) return fail();
    }
    if (relro_phdr != nullptr && relro_phdr->p_memsz != 0) {
        uintptr_t seg_start = align_down(relro_phdr->p_vaddr);
        uintptr_t seg_end = align_up(relro_phdr->p_vaddr + relro_phdr->p_memsz);
        if (!remote.mprotect(bias + seg_start, seg_end - seg_start, PROT_READ)) return fail();
    }

    // Give the anonymous mappings names that are indistinguishable from ART's
    // own JIT/DEX mappings. Best effort: old kernels simply reject PR_SET_VMA.
    constexpr long kPrSetVma = 0x53564d41;
    constexpr long kPrSetVmaAnonName = 0;
    uintptr_t rx_name = push_string(pid, regs, "dalvik-jit-code-cache");
    uintptr_t rw_name = push_string(pid, regs, "dalvik-DEX data");
    for (size_t i = 0; i < img.phnum; ++i) {
        const auto &ph = img.ph[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;
        uintptr_t seg_start = align_down(ph.p_vaddr);
        uintptr_t seg_end = align_up(ph.p_vaddr + ph.p_memsz);
        uintptr_t name = (ph.p_flags & PF_X) != 0 ? rx_name : rw_name;
        remote.call("libc.so", "prctl",
                    {kPrSetVma, kPrSetVmaAnonName, static_cast<long>(bias + seg_start),
                     static_cast<long>(seg_end - seg_start), static_cast<long>(name)});
    }

    if (dyn.init != 0) {
        std::vector<long> no_args;
        remote_call(pid, regs, bias + dyn.init, return_addr, no_args);
    }
    if (dyn.init_array != 0 && dyn.init_arraysz != 0) {
        if (dyn.init_arraysz % sizeof(uintptr_t) != 0) return fail();
        size_t count = dyn.init_arraysz / sizeof(uintptr_t);
        std::vector<uintptr_t> constructors(count);
        size_t bytes = count * sizeof(uintptr_t);
        if (read_proc(pid, bias + dyn.init_array, constructors.data(), bytes) !=
            static_cast<ssize_t>(bytes)) {
            return fail();
        }
        for (uintptr_t constructor : constructors) {
            if (constructor == 0) continue;
            std::vector<long> no_args;
            remote_call(pid, regs, constructor, return_addr, no_args);
        }
    }

    uintptr_t entry = 0;
    for (size_t i = 0; i < symbol_count; ++i) {
        const ElfW(Sym) *sym = sym_at(i);
        if (sym == nullptr || sym->st_shndx == SHN_UNDEF || sym->st_value == 0) continue;
        const char *name = sym_name(*sym);
        if (name != nullptr && strcmp(name, "entry") == 0) {
            entry = bias + sym->st_value;
            break;
        }
    }
    if (entry == 0) return fail();

    info->base = base;
    info->entry = entry;
    return true;
}

#endif
