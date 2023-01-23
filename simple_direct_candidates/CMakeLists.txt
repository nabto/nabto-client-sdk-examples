set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
include(InstallRequiredSystemLibraries)

set(src simple_direct_candidates_client.cpp)

add_executable(simple_direct_candidates_client "${src}")
target_link_libraries(simple_direct_candidates_client nabto_client)

install(TARGETS simple_direct_candidates_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(WIN32)
  install(FILES ${CMAKE_SOURCE_DIR}/nabto_client_sdk_library/lib/windows-x86_64/nabto_client.dll DESTINATION .)
elseif(UNIX AND NOT APPLE)
  install(FILES ${CMAKE_SOURCE_DIR}/nabto_client_sdk_library/lib/linux-x86_64/libnabto_client.so DESTINATION .)
elseif(APPLE)
  add_custom_command(TARGET simple_direct_candidates_client POST_BUILD COMMAND
    ${CMAKE_INSTALL_NAME_TOOL} -change
    @rpath/libnabto_client.dylib
    @executable_path/libnabto_client.dylib
    $<TARGET_FILE:simple_coap_client>)
  install(FILES ${CMAKE_SOURCE_DIR}/nabto_client_sdk_library/lib/macos-universal/libnabto_client.dylib DESTINATION .)
endif()
