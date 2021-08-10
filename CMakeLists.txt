cmake_minimum_required(VERSION 3.0)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_OSX_ARCHITECTURES x86_64)

project(nabto-client-sdk)

include_directories(include)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "install" CACHE PATH "..." FORCE)
endif()

if(WIN32)
  link_directories(${CMAKE_SOURCE_DIR}/lib/windows)
elseif(UNIX AND NOT APPLE)
  add_library(nabto_client SHARED IMPORTED)
  set_target_properties( nabto_client PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/linux/libnabto_client.so)
  set(CMAKE_INSTALL_RPATH $ORIGIN)
  add_definitions("-Wall")
elseif(APPLE)
  link_directories(${CMAKE_SOURCE_DIR}/lib/macos)
  add_definitions("-Wall")
endif()

add_subdirectory(simple_coap)
add_subdirectory(simple_tunnel)
add_subdirectory(simple_stream)
add_subdirectory(heat_pump)
