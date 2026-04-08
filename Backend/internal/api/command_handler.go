package api

import (
	"errors"
	"net/http"

	"github.com/KGU-FIMS/Backend/internal"
	"github.com/gin-gonic/gin"
)

// handleCreateBaseline : POST /api/agents/:id/baseline
func (s *Server) handleCreateBaseline(c *gin.Context) {
	agentID := c.Param("id")

	var body struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path field required"})
		return
	}

	if s.commandSender == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "command sender not available"})
		return
	}

	err := s.commandSender.SendCreateBaseline(c.Request.Context(), agentID, body.Path)
	if err != nil {
		if errors.Is(err, internal.ErrAgentOffline) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent offline"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "baseline command sent", "agent_id": agentID, "path": body.Path})
}

// handleIntegrityScan : POST /api/agents/:id/scan
func (s *Server) handleIntegrityScan(c *gin.Context) {
	agentID := c.Param("id")

	var body struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path field required"})
		return
	}

	if s.commandSender == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "command sender not available"})
		return
	}

	err := s.commandSender.SendIntegrityScan(c.Request.Context(), agentID, body.Path)
	if err != nil {
		if errors.Is(err, internal.ErrAgentOffline) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent offline"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "scan command sent", "agent_id": agentID, "path": body.Path})
}
