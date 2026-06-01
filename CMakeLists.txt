cmake_minimum_required(VERSION 3.16)
project(tls_gateway VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(tls-gateway src/main.c)
target_compile_options(tls-gateway PRIVATE -Wall -Wextra -Wpedantic -Werror)
