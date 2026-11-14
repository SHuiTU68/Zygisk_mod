#include "zn_api.hpp"

#include <new>

#include "hook_engine.hpp"
#include "zn_loader.hpp"

struct ZnSymbolResolver {
    hook_engine::ElfImage image;
};

namespace {

    int ZnPltHook(void *base_addr, const char *symbol, void *hook_handler, void **original) {
        if (base_addr == nullptr || symbol == nullptr || hook_handler == nullptr) return ZN_FAILED;
        return hook_engine::HookBase(base_addr, symbol, hook_handler, original)
               ? ZN_SUCCESS : ZN_FAILED;
    }

    int ZnInlineHook(void *target, void *addr, void **original) {
        if (target == nullptr || addr == nullptr || original == nullptr) return ZN_FAILED;
        return hook_engine::InlineHook(target, addr, original) ? ZN_SUCCESS : ZN_FAILED;
    }

    int ZnInlineUnhook(void *target) {
        if (target == nullptr) return ZN_FAILED;
        return hook_engine::InlineUnhook(target) ? ZN_SUCCESS : ZN_FAILED;
    }

    ZnSymbolResolver *ZnNewSymbolResolver(const char *path, void *base_addr) {
        if (path == nullptr) return nullptr;
        auto *resolver = new(std::nothrow) ZnSymbolResolver();
        if (resolver == nullptr) return nullptr;
        if (!resolver->image.Open(path, base_addr)) {
            delete resolver;
            return nullptr;
        }
        return resolver;
    }

    void ZnFreeSymbolResolver(ZnSymbolResolver *resolver) {
        delete resolver;
    }

    void *ZnGetBaseAddress(ZnSymbolResolver *resolver) {
        return resolver == nullptr ? nullptr : resolver->image.base();
    }

    void *ZnSymbolLookup(ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
        if (resolver == nullptr || name == nullptr) return nullptr;
        return resolver->image.Lookup(name, prefix, size);
    }

    void ZnForEachSymbols(ZnSymbolResolver *resolver,
                          bool (*callback)(const char *name, void *addr, size_t size, void *data),
                          void *data) {
        if (resolver == nullptr) return;
        resolver->image.ForEach(callback, data);
    }

    int ZnConnectCompanion(void *handle) {
        return zn::connect_companion(handle);
    }

    const ZygiskNextRuntime *ZnGetRuntime() {
        return nullptr;
    }

    ZygiskNextAPI g_api = {
            .pltHook = ZnPltHook,
            .inlineHook = ZnInlineHook,
            .inlineUnhook = ZnInlineUnhook,
            .newSymbolResolver = ZnNewSymbolResolver,
            .freeSymbolResolver = ZnFreeSymbolResolver,
            .getBaseAddress = ZnGetBaseAddress,
            .symbolLookup = ZnSymbolLookup,
            .forEachSymbols = ZnForEachSymbols,
            .connectCompanion = ZnConnectCompanion,
            .getRuntime = ZnGetRuntime,
    };

} // namespace

namespace zn {

    const ZygiskNextAPI *api() {
        return &g_api;
    }

} // namespace zn
