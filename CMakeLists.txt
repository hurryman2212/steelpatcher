cmake_minimum_required(VERSION 3.25)

if(WIN32)
  find_program(STEELPATCHER_POWERSHELL NAMES pwsh powershell REQUIRED)
  execute_process(
    COMMAND
      "${STEELPATCHER_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File
      "${CMAKE_CURRENT_SOURCE_DIR}/generate_version.ps1"
    OUTPUT_VARIABLE STEELPATCHER_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
else()
  execute_process(
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/generate-version.sh"
    OUTPUT_VARIABLE STEELPATCHER_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
endif()
if(STEELPATCHER_VERSION STREQUAL "")
  message(FATAL_ERROR "version generator returned an empty version")
endif()

project(steelpatcher LANGUAGES CXX)
message(STATUS "steelpatcher version: ${STEELPATCHER_VERSION}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
foreach(configuration IN LISTS CMAKE_CONFIGURATION_TYPES)
  string(TOUPPER "${configuration}" configuration_upper)
  set("CMAKE_RUNTIME_OUTPUT_DIRECTORY_${configuration_upper}"
      "${CMAKE_BINARY_DIR}/bin")
endforeach()

add_subdirectory(steelupdater)

find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
set(STEELPATCHER_GENERATED_PYTHON_DIRECTORY
    "${CMAKE_BINARY_DIR}/generated-python")
set(STEELPATCHER_GENERATED_VERSION_MODULE
    "${STEELPATCHER_GENERATED_PYTHON_DIRECTORY}/_steelpatcher_build_version.py")
file(MAKE_DIRECTORY "${STEELPATCHER_GENERATED_PYTHON_DIRECTORY}")
file(
  CONFIGURE
  OUTPUT "${STEELPATCHER_GENERATED_VERSION_MODULE}"
  CONTENT "VERSION = \"@STEELPATCHER_VERSION@\"\n"
  @ONLY
  NEWLINE_STYLE UNIX)

function(add_python_executable program)
  set(pyinstaller_directory
      "${CMAKE_BINARY_DIR}/pyinstaller-${program}")
  set(executable
      "${CMAKE_BINARY_DIR}/bin/${program}${CMAKE_EXECUTABLE_SUFFIX}")
  file(
    GLOB_RECURSE python_sources
    CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${program}/*.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/steelpatcher/*.py")
  add_custom_command(
    OUTPUT "${executable}"
    COMMAND
      ${CMAKE_COMMAND} -E env
      "PYINSTALLER_CONFIG_DIR=${CMAKE_BINARY_DIR}/pyinstaller-config-${program}"
      ${Python3_EXECUTABLE} -m PyInstaller --noconfirm --clean --onefile
      --console --name "${program}" --paths "${CMAKE_CURRENT_SOURCE_DIR}"
      --paths "${STEELPATCHER_GENERATED_PYTHON_DIRECTORY}" --hidden-import
      _steelpatcher_build_version
      --distpath "${CMAKE_BINARY_DIR}/bin" --workpath
      "${pyinstaller_directory}" --specpath "${pyinstaller_directory}"
      "${CMAKE_CURRENT_SOURCE_DIR}/${program}/__main__.py"
    DEPENDS
      ${python_sources} "${CMAKE_CURRENT_SOURCE_DIR}/pyproject.toml"
      "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      "${STEELPATCHER_GENERATED_VERSION_MODULE}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    VERBATIM)
  add_custom_target(${program} ALL DEPENDS "${executable}")
endfunction()

add_python_executable(steelpatcher)
add_python_executable(ggpatcher)
