find_package( Threads )

set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
include(InstallRequiredSystemLibraries)

set(src simple_stream_client.cpp)

add_executable(simple_stream_client "${src}")
target_link_libraries(simple_stream_client nabto_client ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS simple_stream_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install_dependencies(simple_stream_client)
