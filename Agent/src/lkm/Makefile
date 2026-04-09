# src/lkm/Makefile — fim_lkm 커널 모듈 빌드
#
# 커널 버전을 자동 감지하여 최적의 hooks 구현을 선택한다.
#
#   < 4.2  : hooks/lkm310.c   sys_call_table (direct args)
#             CentOS 7 (3.10), Ubuntu 14.04 (3.13)
#
#   4.2 ~ 4.14 : hooks/lkm42.c   LSM 훅 주입 (security_hook_heads writable)
#             Ubuntu 16.04 (4.4)
#
#   4.15 ~ 5.6 : hooks/lkm415.c  LSM 훅 주입 + set_memory_rw 페이지 보호 우회
#             Ubuntu 18.04 (4.15), CentOS 8 / RHEL 8 (4.18), Ubuntu 20.04 (5.4)
#
#   >= 5.7 : LKM 불필요 — eBPF LSM(5.8+) 사용 권장
#            (빌드는 가능하나 kallsyms_lookup_name unexported 주의 — lkm415.c kprobe 우회 포함)
#
# HOOKS_IMPL=syscall 강제 선택:
#   < 4.17  : hooks/lkm310.c   (direct args)
#   >= 4.17 : hooks/lkm417_syscall.c  (pt_regs)
#
# 사용법:
#   make                               → 현재 실행 중인 커널 기준 자동 선택
#   make KVER=4.18.0-305.el8.x86_64   → 특정 커널 버전 지정
#   make HOOKS_IMPL=syscall            → LSM 대신 sys_call_table 강제 사용
#   make load                          → 빌드 + insmod
#   make unload                        → rmmod
#   make reload                        → rmmod + insmod

KVER ?= $(shell uname -r)
KDIR  = /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

# ── 커널 버전 파싱 ─────────────────────────────────────────
KVER_MAJOR := $(shell echo $(KVER) | cut -d. -f1)
KVER_MINOR := $(shell echo $(KVER) | cut -d. -f2)
KVER_NUM   := $(shell expr $(KVER_MAJOR) \* 100 + $(KVER_MINOR))

# ── hooks 구현 선택 ────────────────────────────────────────
# HOOKS_IMPL=syscall 로 강제 지정 가능
HOOKS_IMPL ?= auto

ifeq ($(HOOKS_IMPL), syscall)
    # 강제: sys_call_table 방식
    ifeq ($(shell expr $(KVER_NUM) \>= 417), 1)
        HOOKS_OBJ := hooks/lkm417_syscall.o
        HOOKS_TAG := sys_call_table pt_regs (>=4.17, forced)
    else
        HOOKS_OBJ := hooks/lkm310.o
        HOOKS_TAG := sys_call_table direct-args (<4.17, forced)
    endif
else
    # auto: 커널 버전 기준 최적 방식 선택
    ifeq ($(shell expr $(KVER_NUM) \>= 415), 1)
        HOOKS_OBJ := hooks/lkm415.o
        HOOKS_TAG := LSM injection + set_memory_rw (>=4.15)
    else ifeq ($(shell expr $(KVER_NUM) \>= 402), 1)
        HOOKS_OBJ := hooks/lkm42.o
        HOOKS_TAG := LSM injection (4.2~4.14)
    else
        HOOKS_OBJ := hooks/lkm310.o
        HOOKS_TAG := sys_call_table direct-args (<4.2)
    endif
endif

# ── 빌드 대상 ─────────────────────────────────────────────
obj-m := fim_lkm.o

fim_lkm-y := fim_lkm_main.o    \
             fim_lkm_policy.o  \
             fim_lkm_events.o  \
             fim_lkm_chardev.o \
             $(HOOKS_OBJ)

ccflags-y := -Wall -Wextra -I$(src)

# ── 기본 타깃 ─────────────────────────────────────────────
all:
	@echo "  [fim_lkm] kernel=$(KVER)  hooks=$(HOOKS_TAG)"
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

dev-perm:
	sudo chmod 666 /dev/fim_lkm

.PHONY: all clean load unload reload dev-perm
