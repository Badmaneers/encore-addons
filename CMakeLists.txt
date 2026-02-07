cmake_minimum_required(VERSION 3.14)
project(encore_bypass_charging C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ─── Build options ─────────────────────────────────────────────────────
option(STATIC_LINK "Build with static linking" ON)
option(BUILD_TESTS "Build test harness" OFF)
option(ANDROID_BUILD "Build for Android (aarch64)" OFF)

# ─── Compiler flags ───────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3)
else()
    add_compile_options(-O0 -g)
endif()

# ─── Include directories ──────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ─── Source files ─────────────────────────────────────────────────────
set(SOURCES
    src/main.c
    src/logging.c
    src/file_io.c
    src/device_probe.c
    src/bypass_charging.c
    src/license_manager.c
    src/safety_monitor.c
    src/file_watcher.c
    src/crypto_utils.c
    src/anti_tamper.c
)

# ─── Main binary ─────────────────────────────────────────────────────
add_executable(bypass_daemon ${SOURCES})

target_link_libraries(bypass_daemon pthread)

# ─── Find and link libcurl ────────────────────────────────────────────
find_package(CURL QUIET)
if(CURL_FOUND)
    target_include_directories(bypass_daemon PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(bypass_daemon ${CURL_LIBRARIES})
else()
    # Try pkg-config fallback
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CURL QUIET libcurl)
        if(CURL_FOUND)
            target_include_directories(bypass_daemon PRIVATE ${CURL_INCLUDE_DIRS})
            target_link_libraries(bypass_daemon ${CURL_LINK_LIBRARIES})
        else()
            target_link_libraries(bypass_daemon curl)
        endif()
    else()
        target_link_libraries(bypass_daemon curl)
    endif()
endif()

# ─── Find and link OpenSSL ────────────────────────────────────────────
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    target_include_directories(bypass_daemon PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(bypass_daemon OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(bypass_daemon ssl crypto)
endif()

# ─── Static linking ──────────────────────────────────────────────────
if(STATIC_LINK)
    set_target_properties(bypass_daemon PROPERTIES LINK_FLAGS "-static")
endif()

# ─── Install ──────────────────────────────────────────────────────────
install(TARGETS bypass_daemon DESTINATION bin)

# ─── Tests ────────────────────────────────────────────────────────────
if(BUILD_TESTS)
    enable_testing()

    add_executable(test_license tests/test_license.c
                   src/license_manager.c src/device_probe.c
                   src/logging.c src/file_io.c src/crypto_utils.c)
    target_include_directories(test_license PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(test_license pthread curl ssl crypto)
    add_test(NAME test_license COMMAND test_license)

    add_executable(test_device_probe tests/test_device_probe.c
                   src/device_probe.c src/logging.c src/file_io.c)
    target_include_directories(test_device_probe PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(test_device_probe pthread)
    add_test(NAME test_device_probe COMMAND test_device_probe)

    add_executable(test_bypass tests/test_bypass.c
                   src/bypass_charging.c src/logging.c src/file_io.c)
    target_include_directories(test_bypass PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(test_bypass pthread)
    add_test(NAME test_bypass COMMAND test_bypass)
endif()
