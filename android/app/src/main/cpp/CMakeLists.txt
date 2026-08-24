cmake_minimum_required(VERSION 3.22.1)

project(layergram_mlkem LANGUAGES C)

set(LAYERGRAM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")
set(LAYERGRAM_MLKEM_DIR "${LAYERGRAM_ROOT}/native/layergram_mlkem")
set(LAYERGRAM_UPSTREAM_DIR "${LAYERGRAM_ROOT}/third_party/mlkem-native/mlkem")
set(LAYERGRAM_UPSTREAM_TEST_DIR "${LAYERGRAM_ROOT}/third_party/mlkem-native/test")

add_library(
  layergram_mlkem
  SHARED
  "${LAYERGRAM_MLKEM_DIR}/layergram_mlkem.c"
)

target_compile_features(layergram_mlkem PRIVATE c_std_99)
target_compile_definitions(layergram_mlkem PRIVATE LG_MLKEM_BUILD=1)
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
  -Wall
  -Wextra
  -Werror
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wshadow
  -Wpointer-arith
  -Wmissing-prototypes
)
set_target_properties(
  layergram_mlkem
  PROPERTIES
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
)
target_link_options(
  layergram_mlkem
  PRIVATE
  "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/layergram_mlkem.exports.map"
  "-Wl,--no-undefined"
)
