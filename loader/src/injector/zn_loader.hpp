#pragma once

namespace zn {

    // Load every Zygisk Next module that targets the current process.
    void load_all_modules();

    // Resolve the companion socket for a module handle received in
    // onModuleLoaded().
    int connect_companion(void *handle);

} // namespace zn
