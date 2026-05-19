package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal/api"
	"github.com/KN-IG/KN-IG/Backend/internal/collector"
	"github.com/KN-IG/KN-IG/Backend/internal/config"
	"github.com/KN-IG/KN-IG/Backend/internal/engine"
	"github.com/KN-IG/KN-IG/Backend/internal/enrollment"
	"github.com/KN-IG/KN-IG/Backend/internal/store"
)

func main() {
	if err := config.LoadEnv(); err != nil {
		log.Fatalf(".env 로드 실패: %v", err)
	}

	db, err := store.NewDB()
	if err != nil {
		log.Fatalf("DB 연결 실패: %v", err)
	}
	defer db.Close()
	log.Println("MySQL 연결 성공!")

	httpAddr := envOr("HTTP_ADDR", ":8080")
	tcpAddr := envOr("TCP_ADDR", ":9000")
	caCert := envOr("TLS_CA", "./certs/ca.crt")
	serverCert := envOr("TLS_CERT", "./certs/server.crt")
	serverKey := envOr("TLS_KEY", "./certs/server.key")

	agentStore := store.NewMySQLAgentStore(db.Conn)
	enrollmentStore := store.NewMySQLEnrollmentStore(db.Conn)
	eventStore := store.NewMySQLEventStore(db.Conn)
	alertStore := store.NewMySQLAlertStore(db.Conn)
	authStore := store.NewMySQLAuthStore(db.Conn)

	publisher := api.NewSSEPublisher()
	processor := engine.NewEventProcessor(alertStore)
	auth := api.NewPINAuth(authStore)
	log.Println("콘솔 PIN 인증 활성")

	tlsCfg, err := collector.NewTLSConfig(caCert, serverCert, serverKey)
	if err != nil {
		log.Fatalf("TLS 설정 실패: %v", err)
	}

	tcpServer := collector.NewServer(
		tcpAddr,
		tlsCfg,
		agentStore,
		eventStore,
		alertStore,
		publisher,
		processor.Process,
	)

	server := api.NewServer(agentStore, eventStore, alertStore, publisher, auth)

	errCh := make(chan error, 3)

	go func() {
		log.Printf("TCP 서버 시작: %s", tcpAddr)
		if err := tcpServer.Start(); err != nil {
			errCh <- fmt.Errorf("tcp server: %w", err)
		}
	}()

	if enrollAddr := os.Getenv("ENROLL_ADDR"); enrollAddr != "" {
		agentCACert := envOr("AGENT_CA_CERT", caCert)
		agentCAKey := envOr("AGENT_CA_KEY", "./certs/ca.key")
		pepper := os.Getenv("ENROLL_SECRET_PEPPER")
		if pepper == "" {
			log.Fatal("ENROLL_SECRET_PEPPER 환경변수가 필요합니다")
		}
		keyVault, err := enrollment.NewKeyVaultFromEnv("ENROLL_KEY_KEK")
		if err != nil {
			log.Fatal(err)
		}
		defer keyVault.Close()

		certTTL := envDurationHours("AGENT_CERT_TTL_HOURS", 365*24)
		issuer, err := enrollment.NewCertIssuer(agentCACert, agentCAKey, certTTL)
		if err != nil {
			log.Fatalf("Enrollment 인증서 발급기 초기화 실패: %v", err)
		}
		caPEM, err := os.ReadFile(agentCACert)
		if err != nil {
			log.Fatalf("Agent CA 인증서 로드 실패: %v", err)
		}
		enrollSvc := enrollment.NewService(agentStore, enrollmentStore, issuer, caPEM)
		enrollServer := enrollment.NewServer(enrollAddr, enrollSvc, enrollmentStore, keyVault, pepper)

		go func() {
			log.Printf("XOR Enrollment 서버 시작: %s", enrollAddr)
			if err := enrollServer.Start(); err != nil {
				errCh <- fmt.Errorf("enrollment server: %w", err)
			}
		}()
	}

	go func() {
		log.Printf("HTTP 서버 시작: %s", httpAddr)
		if err := server.Start(httpAddr); err != nil {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationHours(key string, fallbackHours int) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return time.Duration(fallbackHours) * time.Hour
	}
	hours, err := strconv.Atoi(raw)
	if err != nil || hours <= 0 {
		return time.Duration(fallbackHours) * time.Hour
	}
	return time.Duration(hours) * time.Hour
}
