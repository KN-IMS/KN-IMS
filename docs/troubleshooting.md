# KN-IMS 트러블슈팅 기록

## 1. VM IP 재할당으로 인한 인증서 재생성 필요

**증상**  
VM IP가 재할당되어 기존 서버 인증서의 SAN(Subject Alternative Name)과 불일치 발생.

**원인**  
`setup_backend_agent_runtime.sh`의 cert 생성 로직이 전체 셋업과 묶여 있어 cert만 단독으로 재생성 불가.

**해결**  
cert 생성 로직을 `gen_certs.sh`로 분리. `--backend-host` 옵션으로 새 IP를 SAN에 포함시켜 재생성.

```bash
./gen_certs.sh --backend-host <새 VM IP>
```

---

## 2. setup_backend_agent_runtime.sh — VM SSH 대상 형식 오류

**증상**
```
[x] VM SSH 대상 형식이 올바르지 않습니다. user@host 형태로 입력하세요: 192.168.27.132
```
올바른 값을 입력해도 동일 오류 반복.

**원인**  
스크립트 상단 기본값에 `user@host` 형식이 아닌 IP만 하드코딩되어 있었음.

```bash
# 문제
VM_TARGET="192.168.27.132"   # @ 없음 → parse_vm_target() 에서 die
VM_HOST="192.168.27.132"
VM_USER="caterpii"
BACKEND_HOST="caterpii@192.168.27.133"
```

사용자 입력과 관계없이 기본값을 `parse_vm_target()`에 넣어 즉시 실패.

**해결**  
하드코딩 기본값을 전부 빈 문자열로 변경.

```bash
VM_TARGET=""
VM_HOST=""
VM_USER=""
BACKEND_HOST=""
```

---

## 3. Backend 서버 DB 연결 실패

**증상**
```
DB 연결 실패: DB 핑 실패: Error 1698 (28000): Access denied for user 'root'@'localhost'
```

**원인**  
`Backend/.env`에 `root:root` 크리덴셜이 하드코딩되어 있었고, CentOS/Ubuntu의 MySQL은 root 계정이 기본적으로 `auth_socket` 플러그인을 사용해 비밀번호 인증 불가.

**해결**  
MySQL root 계정에 비밀번호 인증 활성화.

```bash
sudo mysql -u root
```
```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';
FLUSH PRIVILEGES;
```

---

## 4. Agent TLS 초기화 실패 — SSL_CTX_new 실패

**증상**
```
agent[6030]: tls: SSL_CTX_new 실패
[WARN] [transport] TLS 컨텍스트 초기화 실패 — transport 비활성화
```

**원인 규명 과정**

### 4-1. cert 파일 존재 여부 확인 → 정상
```
/etc/im_monitor/certs/ca.crt     ✓
/etc/im_monitor/certs/agent.crt  ✓
/etc/im_monitor/certs/agent.key  ✓
```

### 4-2. OpenSSL 동작 확인 → 정상
```bash
openssl s_client -connect 192.168.150.128:9000 -CAfile /etc/im_monitor/certs/ca.crt
# TLSv1.2 핸드셰이크 성공 (handshake_failure는 mTLS 클라이언트 인증서 미제공으로 인한 정상 거절)
```

### 4-3. CMakeCache 오염 확인 → 문제 발견
```
OPENSSL_SSL_LIBRARY = /usr/lib/x86_64-linux-gnu/libssl.so  ← Ubuntu 호스트 경로
OpenSSL version: 3.0.2
```
호스트(Ubuntu, OpenSSL 3.0.2)에서 cmake configure된 CMakeCache가 VM에 들어온 채로 make만 실행됨.

**1차 조치**: VM에서 CMakeCache 삭제 후 재구성.
```bash
cd Agent/build
rm -f CMakeCache.txt
cmake ..
make -j$(nproc)
```
→ `ldd agent | grep ssl` 결과 `libssl.so.10` (OpenSSL 1.0.2k) 으로 정상 링크됨.

### 4-4. 여전히 SSL_CTX_new 실패 → 근본 원인 발견

```bash
nm agent | grep -E "TLS_client_method|SSLv23_client_method|SSL_library_init"
# 결과: U SSLv23_client_method@@libssl.so.10
# SSL_library_init 없음
```

`tls_context.c`가 수정(`M`) 상태였음. 현재 소스에는 `SSL_library_init()` 호출이 있지만, **바이너리는 해당 코드가 추가되기 전 버전으로 컴파일된 상태**.

OpenSSL 1.0.2k는 `SSL_library_init()` 없이 `SSL_CTX_new()` 호출 시 NULL 반환.

**최종 해결**  
수정된 소스로 재빌드.
```bash
cd Agent/build
make -j$(nproc)
```

재빌드 후 확인:
```bash
nm agent | grep SSL_library_init
# U SSL_library_init  ← 정상
```

---

## 환경 정보

| 구분 | 사양 |
|---|---|
| Host | Ubuntu, OpenSSL 3.0.2 |
| Backend VM | CentOS 7, OpenSSL 1.0.2k-fips |
| Agent VM | CentOS 7, OpenSSL 1.0.2k-fips |
| Backend | Go, MySQL |
| Agent | C, CMake, fanotify/LKM |
