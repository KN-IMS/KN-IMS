package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleCreateBaseline : POST /api/agents/:id/baseline
func (s *Server) handleCreateBaseline(c *gin.Context) {
	agentID := c.Param("id")

	var body struct {
		Path string `json:"path"`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "baseline command sent", "agent_id": agentID, "path": body.Path})
}

// handleIntegrityScan : POST /api/agents/:id/scan
func (s *Server) handleIntegrityScan(c *gin.Context) {
	agentID := c.Param("id")

	var body struct {
		Path string `json:"path"`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "scan command sent", "agent_id": agentID, "path": body.Path})
}