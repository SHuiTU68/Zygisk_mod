project(external)

add_library(phmap INTERFACE)
target_include_directories(phmap INTERFACE parallel-hashmap)
target_compile_options(phmap INTERFACE -Wno-unused-value)
