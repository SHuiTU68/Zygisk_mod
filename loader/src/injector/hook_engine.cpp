#include "hook_engine.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "logging.h"

#ifndef ElfW
#define ElfW(type) Elf64_##type
#endif

#ifndef DT_ANDROID_RELA
#define DT_ANDROID_RELA 0x60000011
#endif

namespace hook_engine {

    static size_t PageSize() {
        static size_t page = 0;
        if (page == 0) page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        return page;
    }

    static uintptr_t PageStart(uintptr_t addr) {
        return addr & ~(static_cast<uintptr_t>(PageSize()) - 1);
    }

    static size_t PageLength(uintptr_t addr, size_t len) {
        uintptr_t start = PageStart(addr);
        uintptr_t end = PageStart(addr + len - 1) + PageSize();
        return end - start;
    }

    std::vector<MapInfo> MapInfo::Scan() {
        std::vector<MapInfo> info;
        auto maps = std::unique_ptr<FILE, decltype(&fclose)>(
                fopen("/proc/self/maps", "r"), &fclose);
        if (!maps) return info;

        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0, end = 0, off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0, dev_minor = 0;
            char perm[5] = {'\0'};
            int path_off = 0;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n",
                       &start, &end, perm, &off, &dev_major, &dev_minor, &inode,
                       &path_off) != 7) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &map = info.emplace_back();
            map.start = start;
            map.end = end;
            map.offset = off;
            map.dev = static_cast<dev_t>(makedev(dev_major, dev_minor));
            map.inode = inode;
            map.is_private = perm[3] == 'p';
            map.path = line + path_off;
            if (perm[0] == 'r') map.perms |= PROT_READ;
            if (perm[1] == 'w') map.perms |= PROT_WRITE;
            if (perm[2] == 'x') map.perms |= PROT_EXEC;
        }
        free(line);
        return info;
    }

    namespace {

        const MapInfo *FindMap(const std::vector<MapInfo> &maps, uintptr_t addr,
                               size_t len, int need_prot) {
            for (const auto &map: maps) {
                if (addr < map.start || addr >= map.end) continue;
                if (len > map.end - addr) return nullptr;
                if ((map.perms & need_prot) != need_prot) return nullptr;
                return &map;
            }
            return nullptr;
        }

        bool IsReadable(const std::vector<MapInfo> &maps, uintptr_t addr, size_t len) {
            return FindMap(maps, addr, len, PROT_READ) != nullptr;
        }

        std::vector<MapInfo> MapsFor(const std::vector<MapInfo> &maps, dev_t dev, ino_t inode) {
            std::vector<MapInfo> out;
            for (const auto &map: maps) {
                if (map.dev == dev && map.inode == inode) out.push_back(map);
            }
            return out;
        }

        uintptr_t BaseFor(const std::vector<MapInfo> &maps) {
            for (const auto &map: maps) {
                if (map.offset == 0) return map.start;
            }
            uintptr_t base = UINTPTR_MAX;
            for (const auto &map: maps) {
                base = std::min(base, map.start - map.offset);
            }
            return base == UINTPTR_MAX ? 0 : base;
        }

        uintptr_t ImageEnd(const std::vector<MapInfo> &maps) {
            uintptr_t end = 0;
            for (const auto &map: maps) end = std::max(end, map.end);
            return end;
        }

        struct DynamicInfo {
            uintptr_t symtab = 0;
            uintptr_t strtab = 0;
            size_t strsz = 0;
            uintptr_t hash = 0;
            uintptr_t gnu_hash = 0;
            uintptr_t rela = 0;
            size_t relasz = 0;
            uintptr_t jmprel = 0;
            size_t pltrelsz = 0;
            long pltrel = 0;
            bool android_packed = false;
        };

        size_t HashSymbolCount(const std::vector<MapInfo> &maps, uintptr_t hash) {
            if (!IsReadable(maps, hash, 2 * sizeof(uint32_t))) return 0;
            return reinterpret_cast<const uint32_t *>(hash)[1];
        }

        size_t GnuHashSymbolCount(const std::vector<MapInfo> &maps, uintptr_t gnu_hash) {
            if (!IsReadable(maps, gnu_hash, 4 * sizeof(uint32_t))) return 0;
            const auto *header = reinterpret_cast<const uint32_t *>(gnu_hash);
            uint32_t nbuckets = header[0];
            uint32_t symoffset = header[1];
            uint32_t bloom_size = header[2];
            uintptr_t buckets_addr = gnu_hash + 4 * sizeof(uint32_t) +
                                     static_cast<uintptr_t>(bloom_size) * sizeof(ElfW(Addr));
            if (!IsReadable(maps, buckets_addr, static_cast<size_t>(nbuckets) * sizeof(uint32_t)))
                return 0;
            const auto *buckets = reinterpret_cast<const uint32_t *>(buckets_addr);
            uint32_t max_sym = symoffset;
            for (uint32_t i = 0; i < nbuckets; ++i) {
                if (buckets[i] > max_sym) max_sym = buckets[i];
            }
            if (max_sym < symoffset) return symoffset;
            uintptr_t chains_addr = buckets_addr + static_cast<uintptr_t>(nbuckets) * sizeof(uint32_t);
            constexpr uint32_t kLimit = 1u << 20;
            for (uint32_t count = 0; count < kLimit; ++count) {
                uintptr_t chain = chains_addr + static_cast<uintptr_t>(max_sym - symoffset) * sizeof(uint32_t);
                if (!IsReadable(maps, chain, sizeof(uint32_t))) return 0;
                uint32_t value = *reinterpret_cast<const uint32_t *>(chain);
                ++max_sym;
                if (value & 1u) break;
            }
            return max_sym;
        }

        bool ParseDynamic(const std::vector<MapInfo> &maps, uintptr_t base,
                          const ElfW(Phdr) *phdr, size_t phnum, DynamicInfo *out) {
            const ElfW(Dyn) *dyn = nullptr;
            size_t dyn_count = 0;
            for (size_t i = 0; i < phnum; ++i) {
                if (phdr[i].p_type == PT_DYNAMIC && phdr[i].p_memsz != 0) {
                    dyn = reinterpret_cast<const ElfW(Dyn) *>(base + phdr[i].p_vaddr);
                    dyn_count = phdr[i].p_memsz / sizeof(ElfW(Dyn));
                    break;
                }
            }
            if (dyn == nullptr) return false;
            if (!IsReadable(maps, reinterpret_cast<uintptr_t>(dyn), dyn_count * sizeof(ElfW(Dyn))))
                return false;

            for (size_t i = 0; i < dyn_count; ++i) {
                switch (dyn[i].d_tag) {
                    case DT_NULL:
                        i = dyn_count;
                        break;
                    case DT_SYMTAB:
                        out->symtab = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_STRTAB:
                        out->strtab = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_STRSZ:
                        out->strsz = dyn[i].d_un.d_val;
                        break;
                    case DT_HASH:
                        out->hash = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_GNU_HASH:
                        out->gnu_hash = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_RELA:
                        out->rela = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_RELASZ:
                        out->relasz = dyn[i].d_un.d_val;
                        break;
                    case DT_JMPREL:
                        out->jmprel = base + dyn[i].d_un.d_ptr;
                        break;
                    case DT_PLTRELSZ:
                        out->pltrelsz = dyn[i].d_un.d_val;
                        break;
                    case DT_PLTREL:
                        out->pltrel = static_cast<long>(dyn[i].d_un.d_val);
                        break;
                    case DT_ANDROID_RELA:
                        out->android_packed = true;
                        break;
                    default:
                        break;
                }
            }
            return out->symtab != 0 && out->strtab != 0;
        }

        size_t SymbolCount(const std::vector<MapInfo> &maps, const DynamicInfo &dyn) {
            size_t count = 0;
            if (dyn.hash != 0) count = HashSymbolCount(maps, dyn.hash);
            if (count == 0 && dyn.gnu_hash != 0) count = GnuHashSymbolCount(maps, dyn.gnu_hash);
            if (count == 0 && dyn.strtab > dyn.symtab) {
                count = (dyn.strtab - dyn.symtab) / sizeof(ElfW(Sym));
            }
            return count;
        }

        const char *SymbolName(const DynamicInfo &dyn, size_t index) {
            auto *sym = reinterpret_cast<const ElfW(Sym) *>(dyn.symtab + index * sizeof(ElfW(Sym)));
            if (sym->st_name == 0 || sym->st_name >= dyn.strsz) return nullptr;
            const char *name = reinterpret_cast<const char *>(dyn.strtab + sym->st_name);
            if (memchr(name, '\0', dyn.strsz - sym->st_name) == nullptr) return nullptr;
            return name;
        }

        bool PatchPointer(uintptr_t slot, uintptr_t value, int perms) {
            uintptr_t page = PageStart(slot);
            size_t len = PageLength(slot, sizeof(uintptr_t));
            int writable = perms | PROT_READ | PROT_WRITE;
            if (mprotect(reinterpret_cast<void *>(page), len, writable) != 0) {
                LOGW("hook: mprotect(rw) failed at %" PRIxPTR ": %s", slot, strerror(errno));
                return false;
            }
            *reinterpret_cast<uintptr_t *>(slot) = value;
            mprotect(reinterpret_cast<void *>(page), len, perms);
            __builtin___clear_cache(reinterpret_cast<char *>(page),
                                    reinterpret_cast<char *>(page + len));
            return true;
        }

        struct RelocationSlot {
            uintptr_t address;
            int perms;
        };

        void ScanRelocs(const std::vector<MapInfo> &maps, uintptr_t base,
                        const DynamicInfo &dyn, uintptr_t table, size_t size,
                        const char *symbol, std::vector<RelocationSlot> *slots) {
            if (table == 0 || size < sizeof(ElfW(Rela))) return;
            if (!IsReadable(maps, table, size)) return;
            size_t count = size / sizeof(ElfW(Rela));
            auto *rela = reinterpret_cast<const ElfW(Rela) *>(table);
            for (size_t i = 0; i < count; ++i) {
                unsigned type = ELF64_R_TYPE(rela[i].r_info);
                unsigned sym_index = ELF64_R_SYM(rela[i].r_info);
#if defined(__aarch64__)
                if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) continue;
#elif defined(__x86_64__)
                if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
#else
                continue;
#endif
                const char *name = SymbolName(dyn, sym_index);
                if (name == nullptr || strcmp(name, symbol) != 0) continue;
                uintptr_t slot = base + rela[i].r_offset;
                const MapInfo *map = FindMap(maps, slot, sizeof(uintptr_t), PROT_READ);
                if (map == nullptr) continue;
                bool duplicate = false;
                for (const auto &existing: *slots) {
                    if (existing.address == slot) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) slots->push_back(RelocationSlot{slot, map->perms});
            }
        }

        struct PendingHook {
            dev_t dev;
            ino_t inode;
            std::string symbol;
            void *fn;
            void **backup;
        };

        struct PltRecord {
            dev_t dev;
            ino_t inode;
            std::string symbol;
            void *original;
            std::vector<RelocationSlot> slots;
            std::vector<uintptr_t> saved;
        };

        std::mutex g_lock;
        std::vector<PendingHook> g_pending;
        std::vector<PltRecord> g_records;

        PltRecord *FindRecord(dev_t dev, ino_t inode, const char *symbol) {
            for (auto &record: g_records) {
                if (record.dev == dev && record.inode == inode && record.symbol == symbol)
                    return &record;
            }
            return nullptr;
        }

        bool ResolveOriginal(const std::vector<MapInfo> &maps, uintptr_t base,
                             const char *symbol, uintptr_t slot_value, void **out) {
            void *resolved = dlsym(RTLD_DEFAULT, symbol);
            if (resolved != nullptr) {
                *out = resolved;
                return true;
            }
            // The slot may still point at the lazy-binding resolver inside the
            // image, in which case calling it directly would be unsafe.
            uintptr_t end = ImageEnd(maps);
            if (slot_value >= base && slot_value < end && end > base) {
                return false;
            }
            *out = reinterpret_cast<void *>(slot_value);
            return true;
        }

        bool ApplyPending(PendingHook &pending) {
            PltRecord *record = FindRecord(pending.dev, pending.inode, pending.symbol.c_str());
            if (record != nullptr) {
                if (pending.fn == record->original) {
                    bool restored = false;
                    for (size_t i = 0; i < record->slots.size(); ++i) {
                        if (PatchPointer(record->slots[i].address, record->saved[i],
                                         record->slots[i].perms)) {
                            restored = true;
                        }
                    }
                    if (pending.backup != nullptr) *pending.backup = record->original;
                    g_records.erase(std::remove_if(g_records.begin(), g_records.end(),
                                                   [&](const PltRecord &r) {
                                                       return &r == record;
                                                   }),
                                    g_records.end());
                    return restored;
                }
                bool patched = false;
                for (auto &slot: record->slots) {
                    if (PatchPointer(slot.address, reinterpret_cast<uintptr_t>(pending.fn),
                                     slot.perms)) {
                        patched = true;
                    }
                }
                if (pending.backup != nullptr) *pending.backup = record->original;
                return patched;
            }

            auto maps = MapsFor(MapInfo::Scan(), pending.dev, pending.inode);
            if (maps.empty()) return false;
            uintptr_t base = BaseFor(maps);
            if (base == 0) return false;

            const auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);
            if (!IsReadable(maps, base, sizeof(ElfW(Ehdr)))) return false;
            if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
                ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
                ehdr->e_phentsize != sizeof(ElfW(Phdr))) {
                return false;
            }
            auto *phdr = reinterpret_cast<const ElfW(Phdr) *>(base + ehdr->e_phoff);
            if (!IsReadable(maps, reinterpret_cast<uintptr_t>(phdr),
                            static_cast<size_t>(ehdr->e_phnum) * sizeof(ElfW(Phdr)))) {
                return false;
            }

            DynamicInfo dyn;
            if (!ParseDynamic(maps, base, phdr, ehdr->e_phnum, &dyn)) return false;

            std::vector<RelocationSlot> slots;
            if (dyn.jmprel != 0 && dyn.pltrelsz != 0) {
                if (dyn.pltrel != 0 && dyn.pltrel != DT_RELA) return false;
                ScanRelocs(maps, base, dyn, dyn.jmprel, dyn.pltrelsz, pending.symbol.c_str(), &slots);
            }
            if (dyn.rela != 0 && dyn.relasz != 0) {
                // DT_JMPREL usually points inside DT_RELA; skip the overlap.
                if (!(dyn.jmprel != 0 && dyn.rela <= dyn.jmprel &&
                      dyn.jmprel + dyn.pltrelsz <= dyn.rela + dyn.relasz)) {
                    ScanRelocs(maps, base, dyn, dyn.rela, dyn.relasz, pending.symbol.c_str(), &slots);
                }
            }
            if (slots.empty()) return false;

            uintptr_t original_value = *reinterpret_cast<uintptr_t *>(slots[0].address);
            void *original = nullptr;
            if (!ResolveOriginal(maps, base, pending.symbol.c_str(), original_value, &original))
                return false;

            PltRecord entry;
            entry.dev = pending.dev;
            entry.inode = pending.inode;
            entry.symbol = pending.symbol;
            entry.original = original;
            entry.slots = std::move(slots);
            entry.saved.reserve(entry.slots.size());
            for (auto &slot: entry.slots) {
                entry.saved.push_back(*reinterpret_cast<uintptr_t *>(slot.address));
            }
            for (auto &slot: entry.slots) {
                if (!PatchPointer(slot.address, reinterpret_cast<uintptr_t>(pending.fn),
                                  slot.perms)) {
                    return false;
                }
            }
            if (pending.backup != nullptr) *pending.backup = original;
            g_records.push_back(std::move(entry));
            return true;
        }

#if defined(__aarch64__)

        int64_t SignExtend(uint64_t value, int bits) {
            uint64_t sign = 1ULL << (bits - 1);
            return static_cast<int64_t>((value ^ sign) - sign);
        }

        bool IsBranch(uint32_t ins) { return (ins & 0xFC000000u) == 0x14000000u; }

        bool IsBranchLink(uint32_t ins) { return (ins & 0xFC000000u) == 0x94000000u; }

        bool IsBranchCond(uint32_t ins) { return (ins & 0xFF000010u) == 0x54000000u; }

        bool IsCompareBranch(uint32_t ins) {
            return (ins & 0x7E000000u) == 0x34000000u;
        }

        bool IsTestBranch(uint32_t ins) { return (ins & 0x7E000000u) == 0x36000000u; }

        bool IsAdr(uint32_t ins) { return (ins & 0x9F000000u) == 0x10000000u; }

        bool IsAdrp(uint32_t ins) { return (ins & 0x9F000000u) == 0x90000000u; }

        bool IsLiteralLoad(uint32_t ins) { return (ins & 0x3B000000u) == 0x18000000u; }

        uint32_t EncodeBranch(uintptr_t from, uintptr_t to, bool link) {
            int64_t offset = static_cast<int64_t>(to) - static_cast<int64_t>(from);
            if ((offset & 3) != 0) return 0;
            int64_t imm = offset >> 2;
            if (imm < -(1LL << 25) || imm >= (1LL << 25)) return 0;
            return (link ? 0x94000000u : 0x14000000u) | (static_cast<uint32_t>(imm) & 0x03FFFFFFu);
        }

        struct Emitter {
            uint32_t *code;
            size_t capacity;
            size_t count = 0;

            bool Emit(uint32_t ins) {
                if (count >= capacity) return false;
                code[count++] = ins;
                return true;
            }

            void Align8() {
                while ((count & 1u) != 0) Emit(0xD503201Fu); // nop
            }
        };

        constexpr uint32_t kNop = 0xD503201Fu;
        constexpr uint32_t kBrX16 = 0xD61F0200u;
        constexpr uint32_t kBlrX16 = 0xD63F0200u;

        uint32_t LdrLiteralX16(uint32_t words_to_literal) {
            return 0x58000000u | ((words_to_literal & 0x7FFFFu) << 5) | 16u;
        }

        bool EmitAbsoluteJump(Emitter &e, uintptr_t target, bool link) {
            // LDR X16, [PC + 12]; BR/BLR X16; B +8; .quad target
            if (!e.Emit(LdrLiteralX16(3))) return false;
            if (!e.Emit(link ? kBlrX16 : kBrX16)) return false;
            if (link) {
                if (!e.Emit(0x14000003u)) return false; // B over the literal
            } else {
                if (!e.Emit(kNop)) return false;
            }
            uint32_t low = static_cast<uint32_t>(target & 0xFFFFFFFFu);
            uint32_t high = static_cast<uint32_t>(target >> 32);
            if (!e.Emit(low) || !e.Emit(high)) return false;
            return true;
        }

        bool EmitInsn(Emitter &e, uint32_t ins, uintptr_t pc, uintptr_t tramp_base) {
            uintptr_t dest_pc = tramp_base + e.count * sizeof(uint32_t);

            if (IsBranch(ins) || IsBranchLink(ins)) {
                int64_t imm = SignExtend(ins & 0x03FFFFFFu, 26) << 2;
                uintptr_t target = pc + imm;
                uint32_t branch = EncodeBranch(dest_pc, target, IsBranchLink(ins));
                if (branch != 0) return e.Emit(branch);
                return EmitAbsoluteJump(e, target, IsBranchLink(ins));
            }

            if (IsBranchCond(ins)) {
                int64_t imm = SignExtend((ins >> 5) & 0x7FFFFu, 19) << 2;
                uintptr_t target = pc + imm;
                int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(dest_pc);
                if ((delta & 3) == 0 && delta >= -(1LL << 20) && delta < (1LL << 20)) {
                    uint32_t out = (ins & 0xFF00001Fu) |
                                   ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
                    return e.Emit(out);
                }
                // Invert the condition and skip over an absolute branch.
                uint32_t inverted = ins ^ 0x1u;
                return e.Emit((inverted & 0xFF00001Fu) | (5u << 5)) &&
                       e.Emit(LdrLiteralX16(2)) && e.Emit(kBrX16) &&
                       e.Emit(static_cast<uint32_t>(target & 0xFFFFFFFFu)) &&
                       e.Emit(static_cast<uint32_t>(target >> 32));
            }

            if (IsCompareBranch(ins)) {
                int64_t imm = SignExtend((ins >> 5) & 0x7FFFFu, 19) << 2;
                uintptr_t target = pc + imm;
                int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(dest_pc);
                if ((delta & 3) == 0 && delta >= -(1LL << 20) && delta < (1LL << 20)) {
                    uint32_t out = (ins & 0xFF00001Fu) |
                                   ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5);
                    return e.Emit(out);
                }
                uint32_t inverted = ins ^ 0x01000000u;
                return e.Emit((inverted & 0xFF00001Fu) | (5u << 5)) &&
                       e.Emit(LdrLiteralX16(2)) && e.Emit(kBrX16) &&
                       e.Emit(static_cast<uint32_t>(target & 0xFFFFFFFFu)) &&
                       e.Emit(static_cast<uint32_t>(target >> 32));
            }

            if (IsTestBranch(ins)) {
                // Relocating TBZ/TBNZ needs a multi-instruction expansion; fall
                // back rather than risk corrupting the prologue.
                return false;
            }

            if (IsAdr(ins)) {
                int64_t imm = SignExtend(((ins >> 5) & 0x7FFFFu) << 2 | ((ins >> 29) & 0x3u), 21);
                uintptr_t target = pc + imm;
                uint32_t rd = ins & 0x1Fu;
                uintptr_t page = target & ~0xFFFULL;
                int64_t page_delta = (static_cast<int64_t>(page) -
                                      static_cast<int64_t>(dest_pc & ~0xFFFULL)) >> 12;
                if (page_delta < -(1LL << 20) || page_delta >= (1LL << 20)) return false;
                uint32_t immlo = static_cast<uint32_t>(page_delta) & 0x3u;
                uint32_t immhi = (static_cast<uint32_t>(page_delta) >> 2) & 0x7FFFFu;
                uint32_t adrp = 0x90000000u | (immlo << 29) | (immhi << 5) | rd;
                uint32_t add = 0x91000000u |
                               ((static_cast<uint32_t>(target) & 0xFFFu) << 10) |
                               (rd << 5) | rd;
                return e.Emit(adrp) && e.Emit(add);
            }

            if (IsAdrp(ins)) {
                int64_t imm = SignExtend((((ins >> 5) & 0x7FFFFu) << 2) | ((ins >> 29) & 0x3u), 21) << 12;
                uintptr_t target_page = (pc & ~0xFFFULL) + imm;
                uint32_t rd = ins & 0x1Fu;
                int64_t page_delta = (static_cast<int64_t>(target_page) -
                                      static_cast<int64_t>(dest_pc & ~0xFFFULL)) >> 12;
                if (page_delta < -(1LL << 20) || page_delta >= (1LL << 20)) return false;
                uint32_t immlo = static_cast<uint32_t>(page_delta) & 0x3u;
                uint32_t immhi = (static_cast<uint32_t>(page_delta) >> 2) & 0x7FFFFu;
                return e.Emit(0x90000000u | (immlo << 29) | (immhi << 5) | rd);
            }

            if (IsLiteralLoad(ins)) {
                if ((ins & 0x04000000u) != 0) return false; // SIMD literal load
                int64_t imm = SignExtend((ins >> 5) & 0x7FFFFu, 19) << 2;
                uintptr_t target = pc + imm;
                int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(dest_pc);
                if ((delta & 3) == 0 && delta >= -(1LL << 20) && delta < (1LL << 20)) {
                    return e.Emit((ins & 0xFF00001Fu) |
                                  ((static_cast<uint32_t>(delta >> 2) & 0x7FFFFu) << 5));
                }
                uint32_t opc = (ins >> 30) & 0x3u;
                uint32_t rt = ins & 0x1Fu;
                uint32_t load = 0;
                switch (opc) {
                    case 0: load = 0xB9800000u; break; // LDRSW Xt, [X16]
                    case 1: load = 0xB9400000u; break; // LDR Wt, [X16]
                    case 2: load = 0xF9400000u; break; // LDR Xt, [X16]
                    case 3: load = 0xF9800000u; break; // PRFM, [X16]
                    default: return false;
                }
                load |= (16u << 5) | rt;
                return e.Emit(LdrLiteralX16(3)) && e.Emit(load) && e.Emit(kNop) &&
                       e.Emit(static_cast<uint32_t>(target & 0xFFFFFFFFu)) &&
                       e.Emit(static_cast<uint32_t>(target >> 32));
            }

            return e.Emit(ins);
        }

        void *AllocTrampoline() {
            void *mem = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) return nullptr;
            return mem;
        }

        struct InlineRecord {
            uint32_t saved[4];
            void *trampoline;
            size_t size;
        };

        std::unordered_map<uintptr_t, InlineRecord> g_inline;

        bool WriteCode(uintptr_t address, const uint32_t *code, size_t count, int perms) {
            uintptr_t page = PageStart(address);
            size_t len = PageLength(address, count * sizeof(uint32_t));
            if (mprotect(reinterpret_cast<void *>(page), len, perms | PROT_READ | PROT_WRITE) != 0)
                return false;
            memcpy(reinterpret_cast<void *>(address), code, count * sizeof(uint32_t));
            mprotect(reinterpret_cast<void *>(page), len, perms);
            __builtin___clear_cache(reinterpret_cast<char *>(address),
                                    reinterpret_cast<char *>(address + count * sizeof(uint32_t)));
            return true;
        }

#endif // __aarch64__

    } // namespace

    bool RegisterHook(dev_t dev, ino_t inode, const char *symbol, void *fn, void **backup) {
        if (dev == 0 || inode == 0 || symbol == nullptr || fn == nullptr) return false;
        std::lock_guard<std::mutex> guard(g_lock);
        g_pending.push_back(PendingHook{dev, inode, symbol, fn, backup});
        return true;
    }

    bool CommitHook() {
        std::vector<PendingHook> pending;
        {
            std::lock_guard<std::mutex> guard(g_lock);
            pending.swap(g_pending);
        }
        if (pending.empty()) return true;
        std::lock_guard<std::mutex> guard(g_lock);
        bool ok = true;
        for (auto &item: pending) {
            if (!ApplyPending(item)) ok = false;
        }
        return ok;
    }

    bool HookBase(void *base_addr, const char *symbol, void *fn, void **backup) {
        if (base_addr == nullptr || symbol == nullptr || fn == nullptr) return false;
        auto maps = MapInfo::Scan();
        uintptr_t address = reinterpret_cast<uintptr_t>(base_addr);
        for (const auto &map: maps) {
            if (address < map.start || address >= map.end) continue;
            if (!RegisterHook(map.dev, map.inode, symbol, fn, backup)) return false;
            return CommitHook();
        }
        return false;
    }

    bool InlineHook(void *target, void *replace, void **original) {
#if defined(__aarch64__)
        if (target == nullptr || replace == nullptr || original == nullptr) return false;
        std::lock_guard<std::mutex> guard(g_lock);
        uintptr_t address = reinterpret_cast<uintptr_t>(target);
        if (g_inline.count(address) != 0) return false;

        auto maps = MapInfo::Scan();
        const MapInfo *map = FindMap(maps, address, 4 * sizeof(uint32_t), PROT_READ);
        if (map == nullptr) return false;

        auto *trampoline = static_cast<uint32_t *>(AllocTrampoline());
        if (trampoline == nullptr) return false;

        Emitter emitter{trampoline, 4096 / sizeof(uint32_t)};
        for (size_t i = 0; i < 4; ++i) {
            uint32_t ins = *reinterpret_cast<const uint32_t *>(address + i * 4);
            if (!EmitInsn(emitter, ins, address + i * 4,
                          reinterpret_cast<uintptr_t>(trampoline))) {
                munmap(trampoline, 4096);
                return false;
            }
        }
        emitter.Align8();
        uintptr_t resume = address + 4 * sizeof(uint32_t);
        if (!emitter.Emit(LdrLiteralX16(2)) || !emitter.Emit(kBrX16) ||
            !emitter.Emit(static_cast<uint32_t>(resume & 0xFFFFFFFFu)) ||
            !emitter.Emit(static_cast<uint32_t>(resume >> 32))) {
            munmap(trampoline, 4096);
            return false;
        }

        size_t code_size = emitter.count * sizeof(uint32_t);
        if (mprotect(trampoline, 4096, PROT_READ | PROT_EXEC) != 0) {
            munmap(trampoline, 4096);
            return false;
        }
        __builtin___clear_cache(reinterpret_cast<char *>(trampoline),
                                reinterpret_cast<char *>(trampoline) + code_size);

        uint32_t patch[4] = {
                0x58000050u, // ldr x16, #8
                kBrX16,      // br x16
                static_cast<uint32_t>(resume & 0xFFFFFFFFu),
                static_cast<uint32_t>(resume >> 32),
        };
        uint32_t saved[4];
        memcpy(saved, reinterpret_cast<void *>(address), sizeof(saved));
        if (!WriteCode(address, patch, 4, map->perms)) {
            munmap(trampoline, 4096);
            return false;
        }

        g_inline.emplace(address, InlineRecord{{saved[0], saved[1], saved[2], saved[3]},
                                               trampoline, 4096});
        *original = trampoline;
        return true;
#else
        (void) target;
        (void) replace;
        (void) original;
        return false;
#endif
    }

    bool InlineUnhook(void *target) {
#if defined(__aarch64__)
        if (target == nullptr) return false;
        std::lock_guard<std::mutex> guard(g_lock);
        uintptr_t address = reinterpret_cast<uintptr_t>(target);
        auto it = g_inline.find(address);
        if (it == g_inline.end()) return false;
        auto maps = MapInfo::Scan();
        const MapInfo *map = FindMap(maps, address, 4 * sizeof(uint32_t), PROT_READ);
        int perms = map != nullptr ? map->perms : (PROT_READ | PROT_EXEC);
        // Keep the trampoline mapped: a thread may still be executing it.
        if (!WriteCode(address, it->second.saved, 4, perms)) return false;
        g_inline.erase(it);
        return true;
#else
        (void) target;
        return false;
#endif
    }

    bool ElfImage::Open(const char *path, void *base_addr) {
        if (path == nullptr) return false;
        maps_ = MapInfo::Scan();
        if (base_addr != nullptr) {
            base_ = reinterpret_cast<uintptr_t>(base_addr);
        } else {
            std::string target(path);
            uintptr_t fallback = 0;
            for (const auto &map: maps_) {
                if (map.path.empty()) continue;
                bool match = target.find('/') != std::string::npos
                             ? map.path == target
                             : map.path.size() >= target.size() &&
                               map.path.compare(map.path.size() - target.size(),
                                                target.size(), target) == 0;
                if (!match) continue;
                if (map.offset == 0) {
                    base_ = map.start;
                    break;
                }
                if (fallback == 0) fallback = map.start - map.offset;
            }
            if (base_ == 0) base_ = fallback;
        }
        if (base_ == 0) return false;
        return Parse();
    }

    bool ElfImage::Parse() {
        if (!IsReadable(maps_, base_, sizeof(ElfW(Ehdr)))) return false;
        const auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base_);
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return false;
        if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) return false;
        if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) return false;
        phnum_ = ehdr->e_phnum;
        phdr_ = reinterpret_cast<const void *>(base_ + ehdr->e_phoff);
        if (!IsReadable(maps_, reinterpret_cast<uintptr_t>(phdr_),
                        phnum_ * sizeof(ElfW(Phdr)))) {
            return false;
        }
        const auto *phdr = static_cast<const ElfW(Phdr) *>(phdr_);
        DynamicInfo dyn;
        if (!ParseDynamic(maps_, base_, phdr, phnum_, &dyn)) return false;
        symtab_ = reinterpret_cast<const void *>(dyn.symtab);
        strtab_ = reinterpret_cast<const char *>(dyn.strtab);
        strsz_ = dyn.strsz;
        symcount_ = SymbolCount(maps_, dyn);
        if (symcount_ == 0) return false;
        if (!IsReadable(maps_, dyn.symtab, symcount_ * sizeof(ElfW(Sym)))) return false;
        if (!IsReadable(maps_, dyn.strtab, strsz_)) return false;
        ehdr_ = ehdr;
        return true;
    }

    const char *ElfImage::SymbolName(size_t index) const {
        if (index >= symcount_) return nullptr;
        auto *sym = reinterpret_cast<const ElfW(Sym) *>(
                reinterpret_cast<uintptr_t>(symtab_) + index * sizeof(ElfW(Sym)));
        if (sym->st_name == 0 || sym->st_name >= strsz_) return nullptr;
        const char *name = strtab_ + sym->st_name;
        if (memchr(name, '\0', strsz_ - sym->st_name) == nullptr) return nullptr;
        return name;
    }

    bool ElfImage::IsDefined(const void *sym_ptr) const {
        auto *sym = static_cast<const ElfW(Sym) *>(sym_ptr);
        return sym->st_shndx != SHN_UNDEF && sym->st_value != 0;
    }

    void *ElfImage::Lookup(const char *name, bool prefix, size_t *size) {
        if (name == nullptr || name[0] == '\0') return nullptr;
        size_t len = strlen(name);
        for (size_t i = 0; i < symcount_; ++i) {
            auto *sym = reinterpret_cast<const ElfW(Sym) *>(
                    reinterpret_cast<uintptr_t>(symtab_) + i * sizeof(ElfW(Sym)));
            if (!IsDefined(sym)) continue;
            const char *symbol = SymbolName(i);
            if (symbol == nullptr) continue;
            bool match = prefix ? strncmp(symbol, name, len) == 0 : strcmp(symbol, name) == 0;
            if (!match) continue;
            if (size != nullptr) *size = sym->st_size;
            return reinterpret_cast<void *>(base_ + sym->st_value);
        }
        return nullptr;
    }

    void ElfImage::ForEach(bool (*callback)(const char *, void *, size_t, void *), void *data) {
        if (callback == nullptr) return;
        for (size_t i = 0; i < symcount_; ++i) {
            auto *sym = reinterpret_cast<const ElfW(Sym) *>(
                    reinterpret_cast<uintptr_t>(symtab_) + i * sizeof(ElfW(Sym)));
            if (!IsDefined(sym)) continue;
            const char *name = SymbolName(i);
            if (name == nullptr) continue;
            if (!callback(name, reinterpret_cast<void *>(base_ + sym->st_value),
                          sym->st_size, data)) {
                break;
            }
        }
    }

} // namespace hook_engine
