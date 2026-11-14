cmake_minimum_required(VERSION 3.22.1)
project("loader")

find_package(cxx REQUIRED CONFIG)

add_definitions(-DZKSU_VERSION=\"${ZKSU_VERSION}\")

aux_source_directory(common COMMON_SRC_LIST)
add_library(common STATIC ${COMMON_SRC_LIST})
target_include_directories(common PRIVATE include)
target_link_libraries(common cxx::cxx log)

# Android 15+ devices may use 16 KB memory pages. NDK r28+ aligns shared libraries
# by default, but keep the flags explicit so CI and older toolchains stay consistent.
set(PAGE_SIZE_LINK_FLAGS
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384")

aux_source_directory(injector INJECTOR_SRC_LIST)
add_library(zygisk SHARED ${INJECTOR_SRC_LIST})
target_include_directories(zygisk PRIVATE include)
target_link_libraries(zygisk cxx::cxx log common phmap)
target_link_options(zygisk PRIVATE ${PAGE_SIZE_LINK_FLAGS})

aux_source_directory(ptracer PTRACER_SRC_LIST)
add_executable(libzygisk_ptrace.so ${PTRACER_SRC_LIST})
target_include_directories(libzygisk_ptrace.so PRIVATE include)
target_link_libraries(libzygisk_ptrace.so cxx::cxx log common)
target_link_options(libzygisk_ptrace.so PRIVATE ${PAGE_SIZE_LINK_FLAGS})

add_subdirectory(external)
