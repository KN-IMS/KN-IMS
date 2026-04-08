# src/lkm/Makefile — fim_lkm 커널 모듈 빌드
#
# 단일 소스셋으로 kernel 3.10 / 4.18 / 5.4 모두 대응.
# 타겟 커널의 headers가 설치된 머신에서 실행해야 한다.
#
# 사용법:
#   make              → 빌드
#   make load         → 빌드 + insmod
#   make unload       → rmmod
#   make reload       → rmmod + insmod
#   make KVER=4.18.0-305.el8.x86_64   → 특정 버전 지정

KVER ?= $(shell uname -r)
KDIR  = /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

# ── 빌드 대상 ─────────────────────────────────────────────
obj-m := fim_lkm.o

fim_lkm-y := fim_lkm_main.o    \
             fim_lkm_policy.o  \
             fim_lkm_events.o  \
             fim_lkm_chardev.o \
             fim_lkm_hooks.o

ccflags-y := -Wall -Wextra -I$(src)

# ── 기본 타깃 ─────────────────────────────────────────────
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# ── 개발 편의 타깃 ────────────────────────────────────────
load: all
	sudo insmod fim_lkm.ko
	@echo "--- dmesg ---"
	@dmesg | tail -5

unload:
	-sudo rmmod fim_lkm
	@dmesg | tail -3

reload: unload load

# 테스트용: 디바이스 파일 권한 완화 (개발 환경 전용)
dev-perm:
	sudo chmod 666 /dev/fim_lkm

.PHONY: all clean load unload reload dev-perm
