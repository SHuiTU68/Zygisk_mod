#include "zn_loader.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "daemon.h"
#include "dl.h"
#include "logging.h"
#include "zn_api.hpp"
#include "zygisk_next_api.h"

namespace {

    std::mutex g_lock;
    std::unordered_map<void *, std::string> g_companion_paths;

    std::string ReadProcessName() {
        char buf[256] = {};
        int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        ssize_t len = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (len <= 0) return {};
        return std::string(buf, strnlen(buf, static_cast<size_t>(len)));
    }

    std::string ReadProcessPath() {
        char buf[PATH_MAX] = {};
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len <= 0) return {};
        return std::string(buf, static_cast<size_t>(len));
    }

} // namespace

namespace zn {

    void load_all_modules() {
        std::string process = ReadProcessName();
        std::string path = ReadProcessPath();
        auto plan = zygiskd::GetZnPlan(process, path);
        if (plan.empty()) return;

        LOGI("loading %zu ZN module(s) for %s", plan.size(), process.c_str());
        for (auto &entry: plan) {
            void *handle = DlopenMem(entry.memfd, RTLD_NOW);
            if (handle == nullptr) {
                LOGE("failed to load ZN module %s", entry.path.c_str());
                zygiskd::ReportZnModule(entry.path, false);
                continue;
            }
            auto *module = static_cast<ZygiskNextModule *>(dlsym(handle, "zn_module"));
            if (module == nullptr) {
                LOGE("ZN module %s has no zn_module entry", entry.path.c_str());
                zygiskd::ReportZnModule(entry.path, false);
                continue;
            }
            if (module->target_api_version <= 0 ||
                module->target_api_version > ZYGISK_NEXT_API_VERSION) {
                LOGW("ZN module %s targets unsupported API %d", entry.path.c_str(),
                     module->target_api_version);
                zygiskd::ReportZnModule(entry.path, false);
                continue;
            }
            {
                std::lock_guard<std::mutex> guard(g_lock);
                g_companion_paths[handle] = entry.path;
            }
            if (module->onModuleLoaded != nullptr) {
                module->onModuleLoaded(handle, api());
            }
            zygiskd::ReportZnModule(entry.path, true);
        }
    }

    int connect_companion(void *handle) {
        std::string path;
        {
            std::lock_guard<std::mutex> guard(g_lock);
            auto it = g_companion_paths.find(handle);
            if (it == g_companion_paths.end()) return -1;
            path = it->second;
        }
        return zygiskd::ConnectZnCompanion(path);
    }

} // namespace zn
