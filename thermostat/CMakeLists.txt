find_package( Threads )

set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION .)
include(InstallRequiredSystemLibraries)

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

install_dependencies(thermostat_client)
