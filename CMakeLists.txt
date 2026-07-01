cmake_minimum_required(VERSION 3.22.1)
project("matric_core")

add_library(matric_core SHARED native-lib.cpp)

find_library(log-lib log)
target_link_libraries(matric_core ${log-lib})

target_compile_options(matric_core PRIVATE
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
    -ffunction-sections
    -fdata-sections
)

target_link_options(matric_core PRIVATE
    -Wl,--strip-all
    -Wl,--gc-sections
)
