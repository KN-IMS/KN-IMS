package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// handleListAgents : GET /api/agents — 전체 에이전트 목록 조회

func (s *Server) handleListAgents(c *gin.Context) {
	agents, err := s.agentStore.ListAgents(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, agents)
}

// handleGetAgent : GET /api/agents/:id — 단일 에이전트 상세 조회
// URL 파라미터에서 agent_id를 추출하여 조회
func (s *Server) handleGetAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent, err := s.agentStore.GetAgent(c.Request.Context(), agentID)
	if err == internal.ErrAgentNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, agent)
}

// handleDeleteAgent : DELETE /api/agents/:id — 에이전트 삭제
func (s *Server) handleDeleteAgent(c *gin.Context) {
	agentID := c.Param("id")
	err := s.agentStore.DeleteAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "agent deleted"})
}

// handleUpdateStatus : PUT /api/agents/:id/status — 에이전트 상태 수동 변경
// 관리자가 대시보드에서 직접 상태를 제어할 때 사용
func (s *Server) handleUpdateStatus(c *gin.Context) {
	agentID := c.Param("id")
	var body struct {
		Status int `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status field required (1=online, 0=offline)"})
		return
	}
	err := s.agentStore.UpdateStatus(c.Request.Context(), agentID, body.Status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "status updated"})
}