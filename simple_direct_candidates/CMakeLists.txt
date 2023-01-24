set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
include(InstallRequiredSystemLibraries)

set(src simple_direct_candidates_client.cpp)

add_executable(simple_direct_candidates_client "${src}")
target_link_libraries(simple_direct_candidates_client nabto_client)

install(TARGETS simple_direct_candidates_client RUNTIME DESTINATION .
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install_dependencies(simple_direct_candidates_client)
