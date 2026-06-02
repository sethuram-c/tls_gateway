cmake_minimum_required(VERSION 3.16)
project(tls_gateway VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(tls-gateway
    src/main.c
    src/log.c
)
target_include_directories(tls-gateway PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(tls-gateway PRIVATE -Wall -Wextra -Wpedantic -Werror)

enable_testing()
add_test(NAME startup COMMAND tls-gateway)
add_test(NAME help COMMAND tls-gateway --help)
add_test(NAME version COMMAND tls-gateway --version)
