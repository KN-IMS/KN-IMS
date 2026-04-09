cmake_minimum_required(VERSION 3.16)
project(fim_agent C)

# ── 언어 표준 ───────────────────────────────────
set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── 컴파일 옵션 ────────────────────────────────
add_compile_options(-Wall -Wextra -O2)

# ── 인클루드 경로 ──────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/src)

# ── 서브 모듈 ──────────────────────────────────
add_subdirectory(src/core)

# ── 소스 파일 ──────────────────────────────────
# fanotify_mon.c 제거: inotify가 유일한 realtime monitor
set(REALTIME_SRCS
    src/realtime/inotify_mon.c
)

set(CORE_SRCS
    src/fim_config.c
    src/fim_queue.c
    src/lkm/lkm_client.c
)

# scanner: 파일 해시 검사 구현 완료 후 활성화
# set(SCANNER_SRCS
#     src/scanner/baseline.c
#     src/scanner/walker.c
# )

set(SCANNER_SRCS
    src/scanner/walker.c
    src/scanner/baseline.c
)

set(EBPF_SRCS "")

# transport: gRPC 이벤트 전송 구현 완료 후 활성화
# set(TRANSPORT_SRCS
#     src/transport/grpc_client.c
# )
set(TRANSPORT_SRCS
    src/transport/tls_context.c
    src/transport/protocol.c
    src/transport/tcp_client.c
    src/transport/heartbeat.c
)

# ── 실행 파일 ──────────────────────────────────
add_executable(fim_agent
    src/main.c
    ${REALTIME_SRCS}
    ${CORE_SRCS}
    ${TRANSPORT_SRCS}
    ${SCANNER_SRCS}
    ${EBPF_SRCS}
)

# OpenSSL: mTLS transport 의존성
# OpenSSL::SSL / OpenSSL::Crypto imported target은 CMake 3.4+ + OpenSSL 1.1+
# 구버전(CentOS7 cmake2.8, OpenSSL 1.0.x) 대응 fallback 포함
find_package(OpenSSL REQUIRED)

if(TARGET OpenSSL::SSL)
    set(OPENSSL_LINK_LIBS OpenSSL::SSL OpenSSL::Crypto)
else()
    # 구버전 cmake / libssl-dev 미설치 환경 fallback:
    # full path 대신 링커 플래그(-lssl -lcrypto) 사용
    # → 버전 심링크(libssl.so) 없어도 libssl.so.x.x 찾음
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_LINK_LIBS ssl crypto)
endif()

target_link_libraries(fim_agent fim_core pthread ${OPENSSL_LINK_LIBS})

# ── libbpf 선택적 의존성 (eBPF who-data 추적용) ──
# 요구 사항: kernel 5.8+, libbpf >= 0.6
# 런타임 커널 버전 체크는 main.c get_kernel_version()에서 수행
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBBPF QUIET libbpf)
endif()

find_program(CLANG_BIN clang)

if(LIBBPF_FOUND AND CLANG_BIN)
    # ── eBPF skeleton 빌드 (bpf.c → skel.h) ───────
    # skel.h는 반드시 현재 시스템의 bpftool/libbpf로 생성해야 ABI 일치
    add_custom_command(
        OUTPUT  ${CMAKE_SOURCE_DIR}/src/ebpf/fim_trace.skel.h
        COMMAND $(MAKE) -C ${CMAKE_SOURCE_DIR}/src/ebpf
        DEPENDS ${CMAKE_SOURCE_DIR}/src/ebpf/fim_trace.bpf.c
                ${CMAKE_SOURCE_DIR}/src/ebpf/vmlinux.h
        COMMENT "Generating eBPF skeleton (fim_trace.skel.h)"
        VERBATIM
    )
    add_custom_target(ebpf_skel
        DEPENDS ${CMAKE_SOURCE_DIR}/src/ebpf/fim_trace.skel.h
    )

    # fim_trace.c 빌드 포함 + skel.h 인클루드 경로 추가
    list(APPEND EBPF_SRCS src/ebpf/fim_trace.c)
    target_sources(fim_agent PRIVATE src/ebpf/fim_trace.c)
    add_dependencies(fim_agent ebpf_skel)
    target_compile_definitions(fim_agent PRIVATE HAVE_LIBBPF=1)
    target_link_libraries(fim_agent ${LIBBPF_LIBRARIES})
    target_include_directories(fim_agent PRIVATE
        ${LIBBPF_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src/ebpf   # fim_trace.skel.h 위치
    )
    message(STATUS "libbpf found (${LIBBPF_VERSION}) + clang found — eBPF enabled")
elseif(LIBBPF_FOUND AND NOT CLANG_BIN)
    message(STATUS "libbpf found but clang not found — eBPF disabled (inotify-only mode)")
else()
    message(STATUS "libbpf not found — eBPF disabled (inotify-only mode)")
endif()

# ── TODO: gRPC 외부 의존성 ──────────────────────
# fim-common, fim-proto 레포 연동 후 아래 활성화
#
# find_package(Protobuf REQUIRED)
# find_package(gRPC REQUIRED)
# target_link_libraries(fim_agent
#     pthread
#     protobuf::libprotobuf
#     gRPC::grpc++
# )

# ── transport 단독 테스트 바이너리 ─────────────
add_executable(test_transport
    src/transport/test_transport.c
    ${CORE_SRCS}
    ${TRANSPORT_SRCS}
    ${SCANNER_SRCS}
)
target_link_libraries(test_transport fim_core pthread ${OPENSSL_LINK_LIBS})

# ── 설치 ───────────────────────────────────────
install(TARGETS fim_agent DESTINATION bin)
install(FILES configs/agent.yaml
        DESTINATION /etc/fim_monitor
        RENAME fim.conf)
