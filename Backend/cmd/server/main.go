package main

import (
	"log"

	"github.com/KN-IMS/KN-IMS/Backend/internal/api"
	"github.com/KN-IMS/KN-IMS/Backend/internal/store"
)

func main() {
	db, err := store.NewDBWithMigration("internal/store/schema.sql")
	if err != nil {
		log.Fatalf("DB 초기화 실패: %v", err)
	}
	defer db.Close()
	log.Println("MySQL 연결 및 마이그레이션 성공!")

	agentStore := store.NewMySQLAgentStore(db.Conn)
	fileStore := store.NewMySQLFileStore(db.Conn)
	alertStore := store.NewMySQLAlertStore(db.Conn)
	userStore := store.NewMySQLUserStore(db.Conn)

	publisher := api.NewSSEPublisher()

	server := api.NewServer(agentStore, fileStore, alertStore, userStore, publisher, nil)
	server.Start(":8080")
}