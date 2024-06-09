set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
include(InstallRequiredSystemLibraries)

set(src simple_connection_events.cpp)

add_executable(simple_connection_events "${src}")
target_link_libraries(simple_connection_events nabto_client)

install(TARGETS simple_connection_events RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install_dependencies(simple_connection_events)
