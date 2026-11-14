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
+ Built with AGP 8.13, Gradle 8.13, JDK 17 and Android NDK r28
+ Zygisk API v5 (`mount_sysprop_overrides` and the Android 15/16 Zygote signatures)
+ `lsplt` updated to the latest upstream (Android 16 / 16 KB page support)

`PROCESS_ON_DENYLIST` cannot be flagged correctly for isolated processes on Magisk DenyList currently.

Zygisk_mod only guarantees the same behavior of Zygisk API, but will NOT ensure Magisk's internal features.

## Hardening

This fork adds a few process-level hardening measures on top of the original
implementation:

+ loader and module `memfd` mappings are replaced with anonymous, benignly
  named mappings after specialization (`/proc/self/maps` no longer exposes
  their paths)
+ the loader itself is mapped by an in-tree ELF linker instead of the system
  linker, so it never shows up in `soinfo`/`dl_iterate_phdr()`; the mappings
  are anonymous and named like ART JIT/DEX regions. Images that need TLS or
  Android packed relocations automatically fall back to `dlopen`, and arm32
  zygotes keep using `dlopen`
+ the one-shot `strdup` PLT hook is removed after the Zygote JNI hooks are
  installed
+ inherited file descriptors are no longer mass-closed, defeating the
  descriptor-close trap
+ the per-app `/data/adb` control-file check moved into `zygiskd`
+ the loader directory is no longer the well-known `/dev/net0`
