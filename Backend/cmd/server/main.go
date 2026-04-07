package main

import (
	"log"

	"github.com/KGU-FIMS/Backend/internal/api"
	"github.com/KGU-FIMS/Backend/internal/store"
)

func main() {
	db, err := store.NewDB()
	if err != nil {
		log.Fatalf("DB 연결 실패: %v", err)
	}
	defer db.Close()
	log.Println("MySQL 연결 성공!")

	agentStore := store.NewMySQLAgentStore(db.Conn)
	eventStore := store.NewMySQLEventStore(db.Conn)
	scanStore := store.NewMySQLScanStore(db.Conn)
	alertStore := store.NewMySQLAlertStore(db.Conn)

	publisher := api.NewSSEPublisher()

	server := api.NewServer(agentStore, eventStore, scanStore, alertStore, publisher, nil)
	server.Start(":8080")
}