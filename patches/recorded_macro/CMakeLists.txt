cmake_minimum_required(VERSION 3.25)

project(recorded_macro LANGUAGES ASM C)

set(PATCH_COMMON_COMPILE_OPTIONS
    -mcpu=cortex-m4
    -mthumb
    -Os
    -flto
    -ffreestanding
    -fno-builtin
    -fno-common
    -fno-jump-tables
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -ffunction-sections
    -fdata-sections
    -Wall
    -Wextra
    -Wconversion
    -Werror)

foreach(artifact IN ITEMS EXTENSION LOADER FALLBACK)
  if(NOT DEFINED STEELPATCH_${artifact}_ORIGIN OR
     NOT DEFINED STEELPATCH_${artifact}_LENGTH)
    message(FATAL_ERROR "steelpatcher did not provide ${artifact} placement")
  endif()
endforeach()
if(NOT STEELPATCH_DEFINITIONS)
  message(FATAL_ERROR "steelpatcher did not provide target definitions")
endif()

function(add_patch_image target origin length required_symbol)
  add_executable(${target} ${ARGN})
  target_compile_features(${target} PRIVATE c_std_11)
  target_compile_options(${target} PRIVATE ${PATCH_COMMON_COMPILE_OPTIONS})
  target_compile_definitions(${target} PRIVATE ${STEELPATCH_DEFINITIONS})
  target_include_directories(${target} PRIVATE include)
  target_link_options(
    ${target}
    PRIVATE
      -mcpu=cortex-m4
      -mthumb
      -nostdlib
      -flto
      -Wl,--gc-sections
      -Wl,--build-id=none
      -Wl,-u,${required_symbol}
      -Wl,--defsym=PATCH_ORIGIN=${origin}
      -Wl,--defsym=PATCH_LENGTH=${length}
      -T${CMAKE_CURRENT_SOURCE_DIR}/extension.ld
      -Wl,-Map,$<TARGET_FILE_DIR:${target}>/${target}.map)
  set_target_properties(${target} PROPERTIES SUFFIX ".elf")

  add_custom_command(
    TARGET ${target}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${target}>
            $<TARGET_FILE_DIR:${target}>/${target}.bin
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:${target}>
    VERBATIM)
endfunction()

add_patch_image(
  extension
  ${STEELPATCH_EXTENSION_ORIGIN}
  ${STEELPATCH_EXTENSION_LENGTH}
  PatchMacroTriggerPress
  src/firmware_hooks.c
  src/macro_engine.c
  src/patch_runtime.c
  src/single_slot_loader.c)

add_patch_image(
  loader
  ${STEELPATCH_LOADER_ORIGIN}
  ${STEELPATCH_LOADER_LENGTH}
  PatchMappingPressTrampoline
  src/entry.S)
target_link_options(loader PRIVATE -Wl,-u,PatchMappingReleaseTrampoline
                    -Wl,-u,PatchTickTrampoline
                    -Wl,-u,PatchFlashEraseTrampoline
                    -Wl,-u,PatchFlashPushTrampoline
                    -Wl,-u,PatchFlashPullTrampoline)

add_patch_image(
  fallback
  ${STEELPATCH_FALLBACK_ORIGIN}
  ${STEELPATCH_FALLBACK_LENGTH}
  FallbackFlashHandler
  src/fallback_flash.c)
