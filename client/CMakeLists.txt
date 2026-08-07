cmake_minimum_required(VERSION 3.20)
project(czq_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Match the Rust staticlib, which links the dynamic CRT (/defaultlib:msvcrt).
if (MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

# Prebuilt crypto-core staticlib (build it first: `cargo build --release -p crypto-core`).
set(CZQ_CORE_LIB "${CMAKE_CURRENT_SOURCE_DIR}/../target/release/czq_core.lib"
    CACHE FILEPATH "Path to the crypto-core staticlib")

if (NOT EXISTS "${CZQ_CORE_LIB}")
  message(FATAL_ERROR
    "crypto-core staticlib not found at ${CZQ_CORE_LIB}\n"
    "Build it first:  cargo build --release -p crypto-core")
endif()

# --- the client library (wraps the C ABI; the loaders link this) ---
add_library(czq_client STATIC src/client.cpp)
target_include_directories(czq_client PUBLIC include)

set(CZQ_CORE_SYSLIBS bcrypt advapi32 kernel32 ntdll userenv ws2_32 dbghelp)
target_link_libraries(czq_client PUBLIC "${CZQ_CORE_LIB}" ${CZQ_CORE_SYSLIBS})

# --- runnable demo (also exercises the Mehah adapter) ---
add_executable(czq_demo examples/standalone_boot.cpp)
target_include_directories(czq_demo PRIVATE adapters)
target_link_libraries(czq_demo PRIVATE czq_client)
