package api

import (
	"log"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
	"github.com/gin-gonic/gin"
)

// Server : REST API 서버
type Server struct {
	router     *gin.Engine
	agentStore internal.AgentStore
	eventStore internal.EventStore
	alertStore internal.AlertStore
	publisher  internal.EventPublisher
}

// NewServer : 서버 생성
func NewServer(
	agentStore internal.AgentStore,
	eventStore internal.EventStore,
	alertStore internal.AlertStore,
	publisher internal.EventPublisher,
) *Server {
	router := gin.Default()

	s := &Server{
		router:     router,
		agentStore: agentStore,
		eventStore: eventStore,
		alertStore: alertStore,
		publisher:  publisher,
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

	// Alert API
	api.GET("/alerts", s.handleListAlerts)
	api.PATCH("/alerts/:id/resolve", s.handleResolveAlert)
}

// Start : 서버 시작
func (s *Server) Start(addr string) error {
	log.Printf("HTTP 서버 시작: %s", addr)
	return s.router.Run(addr)
}
