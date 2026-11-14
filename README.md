# Zygisk_mod

My change to zygisk  
due to zygisk_next is closesource,there are some opensource implementation  
Standalone implementation of Zygisk, providing Zygisk API support for KernelSU,Apatch and a replacement of Magisk's built-in Zygisk.


## Requirements

### General

+ No multiple root implementation installed

### KernelSU

+ Minimal KernelSU version: 10940
+ Minimal KernelSU Manager (ksud) version: 11424
+ Kernel has full SELinux patch support

### Apatch
+ Minimal Apatch_kernel: 0.10.5
+ Minimal Apatch Manager (apd) version: 10657
+ Kernel has full SELinux patch support

### Magisk

+ Minimal version: 26402
+ Built-in Zygisk turned off
## Credits

- [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext): The opensource code

## Compatibility

+ Android 8.0 - Android 16 (API 26 - 36), including 16 KB page-size devices
+ **64-bit only**: only `arm64-v8a` is built and only the 64-bit Zygote
  (`app_process64`) is injected. 32-bit Zygote, x86 and x86_64 are not supported.
+ Built with AGP 8.13, Gradle 8.13, JDK 17 and Android NDK r28
+ Zygisk API v5 (`mount_sysprop_overrides` and the Android 15/16 Zygote signatures)
+ In-house hook engine (PLT/GOT relocation hooks + arm64 inline hooks + ELF
  symbol resolver) replaces the former `lsplt` dependency
+ Zygisk Next modules: `zn_modules.txt` loading and the ZN API v4
  (`pltHook` / `inlineHook` / symbol resolver / `connectCompanion`) are
  supported for modules targeting `zygote`/`app_process`. Modules selected by
  an app package name or an arbitrary process path are not injected, because
  this module does not perform per-app secondary injection.

`PROCESS_ON_DENYLIST` cannot be flagged correctly for isolated processes on Magisk DenyList currently.

Zygisk_mod only guarantees the same behavior of Zygisk API, but will NOT ensure Magisk's internal features.

## Hardening

This fork adds a few process-level hardening measures on top of the original
implementation:

+ loader and module `memfd` mappings are replaced with anonymous, benignly
  named mappings after specialization (`/proc/self/maps` no longer exposes
  their paths); executable libraries that modules `dlopen` from their own
  module directory are anonymized in the same way
+ the loader itself is mapped by an in-tree ELF linker instead of the system
  linker, so it never shows up in `soinfo`/`dl_iterate_phdr()`; the mappings
  are anonymous and named like ART JIT/DEX regions. The in-tree linker handles
  `DT_RELA`, `RELR` and Android packed relocations (`DT_ANDROID_REL/RELA`,
  APS2); only images that need TLS fall back to `dlopen`
+ hooks are installed by the in-house engine instead of `lsplt`; only the
  64-bit process image is parsed
+ the one-shot `strdup` PLT hook is removed after the Zygote JNI hooks are
  installed
+ inherited file descriptors are no longer mass-closed, defeating the
  descriptor-close trap
+ the per-app `/data/adb` control-file check moved into `zygiskd`
+ the loader directory is no longer the well-known `/dev/net0`; it lives in a
  traversal-only (`0711`) directory, and the loader copy inside it is readable
  by root only
+ the daemons are installed as `bin/d64` / `bin/p64` and the companion /
  monitor sockets use neutral names (`/.m`, `/.c64`), so process listings and
  `/proc/net/unix` no longer contain `zygisk` keywords

## Exclusion modes

Excluded packages can be listed in
`/data/adb/modules/admirepowered/denylist_apps` (one package per line), and the
mode is selected in `/data/adb/modules/admirepowered/denylist_mode`. Both are
merged with the root implementation's own denylist (Magisk DenyList, KernelSU
umount list, APatch exclude list). Two modes are available, matching Zygisk
Next:

+ `just_umount` (default): mounts are reverted for excluded processes, but
  Zygisk modules are still injected and their hooks stay active.
+ `enforce`: mounts are reverted and no Zygisk module is loaded at all.

Change the mode at runtime through the bundled control script:

```sh
/data/adb/modules/admirepowered/bin/ctl denylist just_umount
/data/adb/modules/admirepowered/bin/ctl denylist enforce
/data/adb/modules/admirepowered/bin/ctl denylist   # print current mode
```

Only regular application UIDs (`10000..19999`, any user profile) are matched by
the package list; system UIDs and `system_server` are never affected.
