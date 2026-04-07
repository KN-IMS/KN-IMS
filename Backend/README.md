# FileGuard Backend

## 환경 설정

### 1. MySQL 설치
```bash
sudo apt install -y mysql-server
sudo service mysql start
```

### 2. 데이터베이스 및 사용자 생성
```bash
sudo mysql
```
```sql
CREATE DATABASE fileguard;
CREATE USER '본인아이디'@'localhost' IDENTIFIED BY '본인비밀번호';
GRANT ALL PRIVILEGES ON fileguard.* TO '본인아이디'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. 테이블 생성
```bash
sudo mysql fileguard < internal/store/schema.sql
```

### 4. 환경변수 설정
```bash
cp .env.example .env
```
.env 파일을 열고 본인의 MySQL 정보로 수정
```
DATABASE_URL=본인아이디:본인비밀번호@tcp(localhost:3306)/fileguard?parseTime=true
```

### 5. 실행
```bash
go mod tidy
go run cmd/server/main.go
```
