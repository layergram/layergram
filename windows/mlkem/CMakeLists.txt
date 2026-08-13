cmake_minimum_required(VERSION 3.14)

project(layergram_mlkem LANGUAGES C)

option(
  LAYERGRAM_MLKEM_TESTING
  "Build the deterministic Layergram ML-KEM ABI test hooks and native tests"
  OFF
)

if(NOT MSVC)
  message(FATAL_ERROR "Layergram ML-KEM Windows packaging requires MSVC")
endif()

set(LAYERGRAM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(LAYERGRAM_MLKEM_DIR "${LAYERGRAM_ROOT}/native/layergram_mlkem")
set(LAYERGRAM_UPSTREAM_DIR "${LAYERGRAM_ROOT}/third_party/mlkem-native/mlkem")
set(LAYERGRAM_UPSTREAM_TEST_DIR "${LAYERGRAM_ROOT}/third_party/mlkem-native/test")

add_library(
  layergram_mlkem
  SHARED
  "${LAYERGRAM_MLKEM_DIR}/layergram_mlkem.c"
)

set_target_properties(
  layergram_mlkem
  PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
  OUTPUT_NAME "layergram_mlkem"
  WINDOWS_EXPORT_ALL_SYMBOLS NO
)
target_compile_definitions(
  layergram_mlkem
  PRIVATE
  LG_MLKEM_BUILD=1
  NOMINMAX
  WIN32_LEAN_AND_MEAN
  $<$<BOOL:${LAYERGRAM_MLKEM_TESTING}>:LG_MLKEM_TESTING=1>
)
target_include_directories(
  layergram_mlkem
  PRIVATE
  "${LAYERGRAM_MLKEM_DIR}"
  "${LAYERGRAM_UPSTREAM_DIR}"
  "${LAYERGRAM_UPSTREAM_TEST_DIR}"
)

target_compile_options(
  layergram_mlkem
  PRIVATE
  /W4
  /WX
  /guard:cf
)
target_link_options(layergram_mlkem PRIVATE /guard:cf)

target_link_libraries(layergram_mlkem PRIVATE bcrypt)

if(LAYERGRAM_MLKEM_TESTING)
  enable_testing()
  add_executable(
    layergram_mlkem_abi_test
    "${LAYERGRAM_MLKEM_DIR}/layergram_mlkem_abi_test.c"
  )
  set_target_properties(
    layergram_mlkem_abi_test
    PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
  )
  target_compile_definitions(
    layergram_mlkem_abi_test
    PRIVATE
    LG_MLKEM_TESTING=1
    NOMINMAX
    WIN32_LEAN_AND_MEAN
  )
  target_compile_options(
    layergram_mlkem_abi_test
    PRIVATE
    /W4
    /WX
    /guard:cf
  )
  target_link_options(layergram_mlkem_abi_test PRIVATE /guard:cf)
  target_include_directories(
    layergram_mlkem_abi_test
    PRIVATE
    "${LAYERGRAM_MLKEM_DIR}"
  )
  target_link_libraries(layergram_mlkem_abi_test PRIVATE layergram_mlkem)
  add_test(NAME layergram_mlkem_abi_test COMMAND layergram_mlkem_abi_test)
endif()
