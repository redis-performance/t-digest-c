# Fuzz targets for the t-digest public API.
#
#   -DBUILD_FUZZERS=ON            build the targets
#   -DFUZZ_ENGINE=libfuzzer       link libFuzzer (clang only, the default when available)
#   -DFUZZ_ENGINE=standalone      link a plain main() that replays files (works with gcc)
#   -DFUZZ_ENGINE=oss-fuzz        link $LIB_FUZZING_ENGINE (OSS-Fuzz / ClusterFuzzLite)
#
# Sanitizers are opt-in and orthogonal:
#   -DFUZZ_SANITIZERS="address;undefined"

set(TD_FUZZ_TARGETS
    fuzz_td_api
    fuzz_td_quantile
    fuzz_td_merge
    fuzz_td_init)

if(NOT DEFINED FUZZ_ENGINE OR FUZZ_ENGINE STREQUAL "")
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(FUZZ_ENGINE "libfuzzer")
    else()
        set(FUZZ_ENGINE "standalone")
    endif()
endif()

if(NOT DEFINED FUZZ_SANITIZERS)
    set(FUZZ_SANITIZERS "address;undefined")
endif()

message(STATUS "Fuzzing: engine=${FUZZ_ENGINE} sanitizers=${FUZZ_SANITIZERS}")

# The fuzz targets read td_histogram_t fields directly to assert structural
# invariants, so they compile the library sources in rather than linking the
# installed shared object. This also lets the sanitizer/coverage flags apply to
# the library code itself, which is the point.
set(TD_FUZZ_LIB_SOURCES ${CMAKE_SOURCE_DIR}/src/tdigest.c)

string(REPLACE ";" "," TD_FUZZ_SAN_LIST "${FUZZ_SANITIZERS}")
set(TD_FUZZ_COMMON_FLAGS -g -O1 -fno-omit-frame-pointer)
set(TD_FUZZ_COMMON_LINK "")

if(NOT TD_FUZZ_SAN_LIST STREQUAL "")
    list(APPEND TD_FUZZ_COMMON_FLAGS -fsanitize=${TD_FUZZ_SAN_LIST})
    list(APPEND TD_FUZZ_COMMON_LINK -fsanitize=${TD_FUZZ_SAN_LIST})
    # A fuzzer that stops at the first UB report only ever finds one bug.
    # -DFUZZ_RECOVER=ON keeps going and logs every distinct site, which is what
    # a triage sweep wants; the default halts so CI fails loudly.
    if(FUZZ_RECOVER)
        list(APPEND TD_FUZZ_COMMON_FLAGS -fsanitize-recover=all)
    else()
        list(APPEND TD_FUZZ_COMMON_FLAGS -fno-sanitize-recover=all)
    endif()
endif()

foreach(target ${TD_FUZZ_TARGETS})
    set(sources ${target}.c ${TD_FUZZ_LIB_SOURCES})
    if(FUZZ_ENGINE STREQUAL "standalone")
        list(APPEND sources td_fuzz_standalone.c)
    endif()

    add_executable(${target} ${sources})
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(${target} PRIVATE ${TD_FUZZ_COMMON_FLAGS})
    target_link_libraries(${target} PRIVATE m)
    target_link_options(${target} PRIVATE ${TD_FUZZ_COMMON_LINK})

    if(FUZZ_ENGINE STREQUAL "libfuzzer")
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    elseif(FUZZ_ENGINE STREQUAL "oss-fuzz")
        # OSS-Fuzz supplies the engine and the sanitizer flags via the
        # environment; do not second-guess them here.
        target_link_libraries(${target} PRIVATE $ENV{LIB_FUZZING_ENGINE})
    elseif(NOT FUZZ_ENGINE STREQUAL "standalone")
        message(FATAL_ERROR "Unknown FUZZ_ENGINE '${FUZZ_ENGINE}'")
    endif()
endforeach()

# Replaying the checked-in corpora is cheap and belongs in ctest. Both engines
# accept a list of files as arguments and run each exactly once.
file(GLOB TD_FUZZ_REGRESSIONS ${CMAKE_CURRENT_SOURCE_DIR}/regressions/*)
file(GLOB TD_FUZZ_CORPUS ${CMAKE_CURRENT_SOURCE_DIR}/corpus/*)
foreach(target ${TD_FUZZ_TARGETS})
    if(TD_FUZZ_REGRESSIONS)
        add_test(NAME ${target}_regressions COMMAND ${target} ${TD_FUZZ_REGRESSIONS})
    endif()
    if(TD_FUZZ_CORPUS)
        add_test(NAME ${target}_corpus COMMAND ${target} ${TD_FUZZ_CORPUS})
    endif()
endforeach()
