# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Makefile — im_trace eBPF 빌드 (skeleton 생성)
#
# 출력물:
#   .output/im_trace.bpf.o  — 검증된 BPF 오브젝트 (중간 산출물)
#   im_trace.skel.h          — 유저스페이스 로더(im_trace.c)용 C 스켈레톤 헤더
#
# 사용법:
#   make            빌드 + 스켈레톤 헤더 생성 (기본)
#   make clean      빌드 아티팩트 및 스켈레톤 헤더 삭제
#   make V=1 ...    전체 명령어 출력 (디버깅용)
#
# 의존 도구:
#   clang    — BPF 프로그램 컴파일 (clang -target bpf)
#   bpftool  — BTF 재배치 처리 및 스켈레톤 헤더 생성
#   libbpf   — 시스템 설치 (pkg-config libbpf)

OUTPUT   := .output
CLANG    ?= clang

# bpftool 자동 탐색: PATH → /usr/sbin → linux-tools 커널 버전별 경로
_BPFTOOL_SEARCH := $(shell \
    which bpftool 2>/dev/null \
    || find /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin \
            /usr/lib/linux-tools/$(shell uname -r) \
            /usr/lib/linux-tools \
            -maxdepth 2 -name bpftool -type f 2>/dev/null | head -1)
BPFTOOL ?= $(_BPFTOOL_SEARCH)

# 아키텍처 정규화 — BPF 컴파일 시 __TARGET_ARCH_<arch> 매크로에 사용
ARCH ?= $(shell uname -m \
          | sed 's/x86_64/x86/' \
          | sed 's/aarch64/arm64/' \
          | sed 's/armv.*/arm/')

# vmlinux.h 는 현재 디렉터리에 이미 존재
# <bpf/bpf_helpers.h> 등은 CLANG_BPF_SYS_INCLUDES 로 처리
INCLUDES := -I.

# -target bpf 빌드에서 Clang 기본 시스템 헤더를 -idirafter 로 추가
# (asm/types.h 등 아키텍처 종속 헤더 누락 방지)
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# 출력 제어 — V=1 이면 전체 명령어 표시, 기본은 요약
ifeq ($(V),1)
  Q   =
  msg =
else
  Q   = @
  msg = @printf '  %-12s %s\n' "$(1)" "$(2)";
  MAKEFLAGS += --no-print-directory
endif

APP := im_trace

ifeq ($(BPFTOOL),)
  $(error bpftool not found. Install with: sudo apt install linux-tools-$(shell uname -r) linux-tools-common)
endif

.PHONY: all clean

all: $(APP).skel.h

# ── 빌드 출력 디렉터리 ────────────────────────────────────────────────────────

$(OUTPUT):
	$(Q)mkdir -p $@

# ── 1단계: BPF C 소스 → 원시 BPF ELF 오브젝트 ──────────────────────────────
#
# -g           : BTF 디버그 정보 포함 (CO-RE 필수)
# -O2          : BPF 검증기 통과를 위한 최적화
# -target bpf  : BPF 아키텍처 타겟
# -D__TARGET_ARCH_$(ARCH) : bpf_tracing.h 에서 레지스터 정의 선택에 사용

$(OUTPUT)/$(APP).tmp.bpf.o: $(APP).bpf.c vmlinux.h | $(OUTPUT)
	$(call msg,BPF-CC,$@)
	$(Q)$(CLANG) -g -O2 -target bpf \
	    -D__TARGET_ARCH_$(ARCH) \
	    $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
	    -c $< -o $@

# ── 2단계: bpftool gen object — BTF 재배치(CO-RE) 처리 ───────────────────────
#
# 원시 오브젝트의 BTF 재배치 섹션(.BTF.ext 등)을 처리해
# 로드 가능한 최종 BPF 오브젝트를 생성

$(OUTPUT)/$(APP).bpf.o: $(OUTPUT)/$(APP).tmp.bpf.o
	$(call msg,GEN-OBJ,$@)
	$(Q)$(BPFTOOL) gen object $@ $<

# ── 3단계: bpftool gen skeleton — C 스켈레톤 헤더 생성 ──────────────────────
#
# 유저스페이스(im_trace.c)에서 #include "im_trace.skel.h" 로 사용
# BPF 오브젝트 로드·attach·맵 접근을 위한 래퍼 구조체/함수 자동 생성

$(APP).skel.h: $(OUTPUT)/$(APP).bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# ── 정리 ─────────────────────────────────────────────────────────────────────

clean:
	$(call msg,CLEAN,$(OUTPUT) + $(APP).skel.h)
	$(Q)rm -rf $(OUTPUT) $(APP).skel.h

.DELETE_ON_ERROR:
.SECONDARY:
