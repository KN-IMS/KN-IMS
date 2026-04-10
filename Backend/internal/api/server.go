package api

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// Server : HTTP API 서버 구조체
type Server struct {
	router        *gin.Engine
	agentStore    internal.AgentStore
	fileStore     internal.FileStore
	alertStore    internal.AlertStore
	userStore     internal.UserStore
	publisher     internal.EventPublisher
	commandSender internal.CommandSender
}

// NewServer : Server 생성자
func NewServer(
	agentStore internal.AgentStore,
	fileStore internal.FileStore,
	alertStore internal.AlertStore,
	userStore internal.UserStore,
	publisher internal.EventPublisher,
	commandSender internal.CommandSender,
) *Server {
	router := gin.Default()

	s := &Server{
		router:        router,
		agentStore:    agentStore,
		fileStore:     fileStore,
		alertStore:    alertStore,
		userStore:     userStore,
		publisher:     publisher,
		commandSender: commandSender,
	}

	s.registerRoutes()

	return s
}

// registerRoutes : 모든 API 엔드포인트를 라우터에 등록
func (s *Server) registerRoutes() {
	api := s.router.Group("/api")

	// 인증 불필요 (로그인/회원가입)
	auth := api.Group("/auth")
	auth.POST("/register", s.handleRegister)
	auth.POST("/login", s.handleLogin)

	// 인증 필요 (JWT 미들웨어 적용)
	protected := api.Group("")
	protected.Use(authMiddleware())

	// Agent API
	protected.GET("/agents", s.handleListAgents)
	protected.GET("/agents/:id", s.handleGetAgent)
	protected.DELETE("/agents/:id", s.handleDeleteAgent)
	protected.PUT("/agents/:id/status", s.handleUpdateStatus)

	// Command API
	protected.POST("/agents/:id/baseline", s.handleCreateBaseline)
	protected.POST("/agents/:id/scan", s.handleIntegrityScan)

	// Alert API
	protected.GET("/alerts", s.handleListAlerts)

	// SSE
	protected.GET("/events/stream", s.handleSSE)
}


// Start : HTTP 서버 시작
// addr: 바인딩 주소 (e.g. ":8080")
// main.go에서 호출
func (s *Server) Start(addr string) {
	log.Printf("HTTP 서버 시작: %s", addr)
	if err := s.router.Run(addr); err != nil {
		log.Fatalf("서버 시작 실패: %v", err)
	}
}