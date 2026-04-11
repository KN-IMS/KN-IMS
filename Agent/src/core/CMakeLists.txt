add_library(im_core STATIC
    daemon.c
    pid_lock.c
    event_loop.c
)

# C11 강제 — core 모듈은 C 전용 (main 및 팀원 C++ 코드와 혼용 가능)
set_target_properties(im_core PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
)

target_include_directories(im_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD libsystemd)

if(SYSTEMD_FOUND)
    target_link_libraries(im_core PUBLIC ${SYSTEMD_LIBRARIES})
    target_compile_definitions(im_core PUBLIC HAVE_SYSTEMD)
endif()
