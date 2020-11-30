find_package( Threads )

set(src stream_echo_client.cpp)

add_executable(simple_stream_client "${src}")
target_link_libraries(simple_stream_client nabto_client ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS simple_stream_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(WIN32)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/windows/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/linux/libnabto_client.so DESTINATION .)
elseif(APPLE)
  add_custom_command(TARGET simple_stream_client POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change
    @rpath/libnabto_client.dylib
    @executable_path/libnabto_client.dylib
    $<TARGET_FILE:simple_stream_client>)
  install(FILES ${CMAKE_SOURCE_DIR}/lib/macos/libnabto_client.dylib DESTINATION .)
endif()
