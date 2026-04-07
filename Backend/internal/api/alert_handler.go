package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/KGU-FIMS/Backend/internal"
)

// handleListAlerts : GET /api/alerts
func (s *Server) handleListAlerts(c *gin.Context) {
	filter := internal.AlertFilter{
		AgentID:  c.Query("agent_id"),
		Severity: c.Query("severity"),
	}

	if resolved := c.Query("resolved"); resolved != "" {
		b, err := strconv.ParseBool(resolved)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resolved value"})
			return
		}
		filter.Resolved = &b
	}

	if limit := c.Query("limit"); limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		filter.Limit = n
	}

	if offset := c.Query("offset"); offset != "" {
		n, err := strconv.Atoi(offset)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid offset"})
			return
		}
		filter.Offset = n
	}

	alerts, err := s.alertStore.ListAlerts(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, alerts)
}

// handleResolveAlert : PATCH /api/alerts/:id/resolve
func (s *Server) handleResolveAlert(c *gin.Context) {
	idStr := c.Param("id")
	alertID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert id"})
		return
	}

	err = s.alertStore.ResolveAlert(c.Request.Context(), alertID)
	if err == internal.ErrAlertNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "alert resolved"})
}