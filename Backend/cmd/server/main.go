package main

import (
	"fmt"
	"log"
	"os"

	"github.com/KGU-FIMS/Backend/internal/api"
	"github.com/KGU-FIMS/Backend/internal/collector"
	"github.com/KGU-FIMS/Backend/internal/engine"
	"github.com/KGU-FIMS/Backend/internal/store"
)

func main() {
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
	eventStore := store.NewMySQLEventStore(db.Conn)
	scanStore := store.NewMySQLScanStore(db.Conn)
	alertStore := store.NewMySQLAlertStore(db.Conn)

	publisher := api.NewSSEPublisher()
	processor := engine.NewEventProcessor(alertStore)

	tlsCfg, err := collector.NewTLSConfig(caCert, serverCert, serverKey)
	if err != nil {
		log.Fatalf("TLS 설정 실패: %v", err)
	}

	tcpServer := collector.NewServer(
		tcpAddr,
		tlsCfg,
		agentStore,
		eventStore,
		scanStore,
		alertStore,
		publisher,
		processor.Process,
	)

	server := api.NewServer(agentStore, eventStore, scanStore, alertStore, publisher, tcpServer)

	errCh := make(chan error, 2)

	go func() {
		log.Printf("TCP 서버 시작: %s", tcpAddr)
		if err := tcpServer.Start(); err != nil {
			errCh <- fmt.Errorf("tcp server: %w", err)
		}
	}()

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
