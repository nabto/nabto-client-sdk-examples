find_package( Threads )

set(src
  src/main.cpp
  src/thermostat_requests.cpp
  src/iam_requests.cpp
  src/coap_helper.cpp
  src/pairing.cpp
  src/util.cpp
  )

add_executable(thermostat_client ${src})

target_link_libraries(thermostat_client nabto_client ${CMAKE_THREAD_LIBS_INIT})

target_compile_definitions(thermostat_client PRIVATE -D_CRT_SECURE_NO_WARNINGS)

install(TARGETS thermostat_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(WIN32)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/linux/libnabto_client.so DESTINATION .)
elseif(APPLE)
  add_custom_command(TARGET thermostat_client POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change
    @rpath/libnabto_client.dylib
    @executable_path/libnabto_client.dylib
    $<TARGET_FILE:thermostat_client>)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/macos/libnabto_client.dylib DESTINATION .)
endif()
