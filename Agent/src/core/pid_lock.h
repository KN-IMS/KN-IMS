#ifndef FIM_PID_LOCK_H
#define FIM_PID_LOCK_H

/* fcntl F_SETLK 기반 PID 잠금 획득 (NFS 호환, flock 아님)
 * 비정상 종료 시 OS가 fd를 닫으며 잠금 자동 해제
 * 성공 0, 이미 실행 중이거나 실패 시 -1 반환      */
int pid_lock_acquire(const char *path);

/* 잠금 해제 + PID 파일 삭제 — 중복 호출 안전 */
void pid_lock_release(void);

#endif /* FIM_PID_LOCK_H */
