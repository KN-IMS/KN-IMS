package api

import (
	"log"

	"github.com/KN-IG/KN-IG/Backend/internal"
	"github.com/gin-gonic/gin"
)

// Server : REST API 서버
type Server struct {
	router     *gin.Engine
	agentStore internal.AgentStore
	eventStore internal.EventStore
	alertStore internal.AlertStore
	publisher  internal.EventPublisher
	auth       *PINAuth
}

// NewServer : 서버 생성. PIN 인증 endpoint와 /api/* 보호 미들웨어를 등록한다.
func NewServer(
	agentStore internal.AgentStore,
	eventStore internal.EventStore,
	alertStore internal.AlertStore,
	publisher internal.EventPublisher,
	auth *PINAuth,
) *Server {
	router := gin.Default()
	router.Use(corsMiddleware())

	s := &Server{
		router:     router,
		agentStore: agentStore,
		eventStore: eventStore,
		alertStore: alertStore,
		publisher:  publisher,
		auth:       auth,
	}

	s.registerRoutes()

	return s
}

// registerRoutes : API 엔드포인트 등록
func (s *Server) registerRoutes() {
	if s.auth != nil {
		// 인증 endpoint는 PIN setup/login/status를 위해 공개한다.
		authGrp := s.router.Group("/auth")
		authGrp.GET("/status", s.auth.Status)
		authGrp.POST("/setup", s.auth.Setup)
		authGrp.POST("/login", s.auth.Login)
	}

	api := s.router.Group("/api")
	if s.auth != nil {
		api.Use(s.auth.Authorize)
	}

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

// corsMiddleware : Tauri 콘솔(별 origin)이 직접 호출 가능하도록 허용.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// Start : 서버 시작
func (s *Server) Start(addr string) error {
	log.Printf("HTTP 서버 시작: %s", addr)
	return s.router.Run(addr)
}
