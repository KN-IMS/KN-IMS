package api

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/KGU-FIMS/Backend/internal"
)

// Server : REST API 서버
type Server struct {
	router        *gin.Engine
	agentStore    internal.AgentStore
	eventStore    internal.EventStore
	scanStore     internal.ScanStore
	alertStore    internal.AlertStore
	publisher     internal.EventPublisher
	commandSender internal.CommandSender
}

// NewServer : 서버 생성
func NewServer(
	agentStore internal.AgentStore,
	eventStore internal.EventStore,
	scanStore internal.ScanStore,
	alertStore internal.AlertStore,
	publisher internal.EventPublisher,
	commandSender internal.CommandSender,
) *Server {
	router := gin.Default()

	s := &Server{
		router:        router,
		agentStore:    agentStore,
		eventStore:    eventStore,
		scanStore:     scanStore,
		alertStore:    alertStore,
		publisher:     publisher,
		commandSender: commandSender,
	}

	s.registerRoutes()

	return s
}

// registerRoutes : API 엔드포인트 등록
func (s *Server) registerRoutes() {
	api := s.router.Group("/api")

	// Agent API
	api.GET("/agents", s.handleListAgents)
	api.GET("/agents/:id", s.handleGetAgent)
	api.DELETE("/agents/:id", s.handleDeleteAgent)
	api.PUT("/agents/:id/status", s.handleUpdateStatus)

	// Event API
	api.GET("/events", s.handleQueryEvents)
	api.GET("/events/stream", s.handleSSE)

	// Command API
	api.POST("/agents/:id/baseline", s.handleCreateBaseline)
	api.POST("/agents/:id/scan", s.handleIntegrityScan)

	// Alert API
	api.GET("/alerts", s.handleListAlerts)
	api.PATCH("/alerts/:id/resolve", s.handleResolveAlert)
}

// Start : 서버 시작
func (s *Server) Start(addr string) {
	log.Printf("HTTP 서버 시작: %s", addr)
	if err := s.router.Run(addr); err != nil {
		log.Fatalf("서버 시작 실패: %v", err)
	}
}