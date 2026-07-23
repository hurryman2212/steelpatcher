include(FetchContent)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(HIDAPI_BUILD_HIDTEST OFF CACHE BOOL "" FORCE)
set(HIDAPI_WITH_TESTS OFF CACHE BOOL "" FORCE)
if(UNIX AND NOT APPLE)
  set(HIDAPI_WITH_HIDRAW OFF CACHE BOOL "" FORCE)
endif()
FetchContent_Declare(
  hidapi
  GIT_REPOSITORY https://github.com/libusb/hidapi.git
  GIT_TAG hidapi-0.15.0
  GIT_SHALLOW TRUE)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(hidapi nlohmann_json)

add_executable(steelupdater main.cpp catalog.cpp container.cpp device.cpp updater.cpp)
target_compile_features(steelupdater PRIVATE cxx_std_20)
target_compile_definitions(
  steelupdater PRIVATE NOMINMAX
                       STEELPATCHER_VERSION="${STEELPATCHER_VERSION}")
target_link_libraries(
  steelupdater PRIVATE OpenSSL::Crypto nlohmann_json::nlohmann_json)

if(WIN32)
  target_link_libraries(steelupdater PRIVATE hidapi::winapi)
elseif(TARGET hidapi::libusb)
  target_compile_definitions(hidapi_libusb PRIVATE INVASIVE_GET_USAGE)
  target_link_libraries(steelupdater PRIVATE hidapi::libusb)
else()
  target_link_libraries(steelupdater PRIVATE hidapi::hidapi)
endif()

if(MSVC)
  target_compile_options(steelupdater PRIVATE /W4 /WX /permissive- /EHsc)
else()
  target_compile_options(
    steelupdater
    PRIVATE -Wall -Wextra -Wconversion -Wpedantic -Werror)
endif()
