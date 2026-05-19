package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
	"github.com/KN-IG/KN-IG/Backend/internal/config"
	"github.com/KN-IG/KN-IG/Backend/internal/enrollment"
	"github.com/KN-IG/KN-IG/Backend/internal/store"
)

func main() {
	if err := config.LoadEnv(); err != nil {
		log.Fatalf(".env 로드 실패: %v", err)
	}

	agentID := flag.String("agent-id", "", "사전 지정 agent_id. 비워두면 enrollment 시 hostname/IP로 계산")
	ttlHours := flag.Int("ttl-hours", 24, "XOR bootstrap key 유효 시간")
	flag.Parse()

	if *ttlHours <= 0 {
		log.Fatal("ttl-hours는 1 이상이어야 합니다")
	}

	pepper := os.Getenv("ENROLL_SECRET_PEPPER")
	if pepper == "" {
		log.Fatal("ENROLL_SECRET_PEPPER 환경변수가 필요합니다")
	}
	keyVault, err := enrollment.NewKeyVaultFromEnv("ENROLL_KEY_KEK")
	if err != nil {
		log.Fatal(err)
	}
	defer keyVault.Close()

	db, err := store.NewDB()
	if err != nil {
		log.Fatalf("DB 연결 실패: %v", err)
	}
	defer db.Close()

	enrollmentID, err := enrollment.GenerateID()
	if err != nil {
		log.Fatalf("enrollment_id 생성 실패: %v", err)
	}
	xorKey, err := enrollment.GenerateXORKey()
	if err != nil {
		log.Fatalf("XOR key 생성 실패: %v", err)
	}
	defer enrollment.ZeroBytes(xorKey)

	keyCiphertext, keyNonce, err := keyVault.Encrypt(xorKey)
	if err != nil {
		log.Fatalf("XOR key 암호화 실패: %v", err)
	}

	enrollmentStore := store.NewMySQLEnrollmentStore(db.Conn)
	expiresAt := time.Now().UTC().Add(time.Duration(*ttlHours) * time.Hour)
	row := internal.Enrollment{
		EnrollmentID:  enrollmentID,
		AgentID:       *agentID,
		SecretHash:    enrollment.HashXORKey(enrollmentID, xorKey, pepper),
		KeyCiphertext: keyCiphertext,
		KeyNonce:      keyNonce,
		ExpiresAt:     expiresAt,
	}
	if err := enrollmentStore.CreateEnrollment(context.Background(), row); err != nil {
		log.Fatalf("enrollment 저장 실패: %v", err)
	}

	fmt.Printf("ENROLLMENT_ID=%s\n", enrollmentID)
	fmt.Print("XOR_KEY=")
	if _, err := os.Stdout.Write(xorKey); err != nil {
		log.Fatalf("XOR key 출력 실패: %v", err)
	}
	fmt.Println()
	fmt.Printf("EXPIRES_AT=%s\n", expiresAt.Format(time.RFC3339))
}
