cmake_minimum_required(VERSION 3.10)
project(expense_tracker)

set(CMAKE_CXX_STANDARD 17)

# === Include directories ===
include_directories(include)

# === Source files ===
file(GLOB_RECURSE APP_SOURCES "src/*.cpp")
list(REMOVE_ITEM APP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/test.cpp")  # exclude test.cpp

# === Main executable ===
add_executable(expense_tracker ${APP_SOURCES})
target_link_libraries(expense_tracker sqlite3 argon2)

# === Test executable ===
add_executable(run_tests
    src/test.cpp
    src/database.cpp
    src/memory_log.cpp
)

target_include_directories(run_tests PRIVATE include)
target_link_libraries(run_tests sqlite3 argon2)
