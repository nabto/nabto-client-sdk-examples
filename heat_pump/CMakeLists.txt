find_package( Threads )

set(src
  src/main.cpp
  src/heat_pump_requests.cpp
  src/iam_requests.cpp
  src/coap_helper.cpp
  src/pairing.cpp
  src/timestamp.cpp
  src/client_key.cpp
  src/json_config.cpp
  )

add_executable(heat_pump_client ${src})

target_link_libraries(heat_pump_client nabto_client ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS heat_pump_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(WIN32)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/linux/libnabto_client.so DESTINATION .)
elseif(APPLE)
  add_custom_command(TARGET heat_pump_client POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change
    @rpath/libnabto_client.dylib
    @executable_path/libnabto_client.dylib
    $<TARGET_FILE:edge_tunnel_client>)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/macos/libnabto_client.dylib DESTINATION .)
endif()
