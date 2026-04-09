package api

import (
	"net/http"

	"github.com/KN-IMS/KN-IMS/Backend/internal"
	"github.com/gin-gonic/gin"
)

// handleListAgents : GET /api/agents
func (s *Server) handleListAgents(c *gin.Context) {
	agents, err := s.agentStore.ListAgents(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, agents)
}

// handleGetAgent : GET /api/agents/:id
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

// handleDeleteAgent : DELETE /api/agents/:id
func (s *Server) handleDeleteAgent(c *gin.Context) {
	agentID := c.Param("id")

	err := s.agentStore.DeleteAgent(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "agent deleted"})
}

// handleUpdateStatus : PUT /api/agents/:id/status
func (s *Server) handleUpdateStatus(c *gin.Context) {
	agentID := c.Param("id")

	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status field required"})
		return
	}

	err := s.agentStore.UpdateStatus(c.Request.Context(), agentID, body.Status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "status updated"})
}
