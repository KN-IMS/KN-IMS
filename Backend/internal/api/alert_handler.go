package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/KN-IMS/KN-IMS/Backend/internal"
)

// handleListAlerts : GET /api/alerts
// 무결성 이벤트(알림) 목록을 필터링하여 조회
func (s *Server) handleListAlerts(c *gin.Context) {
	filter := internal.AlertFilter{
		AgentID:   c.Query("agent_id"),
		EventType: c.Query("event_type"),
	}

	if from := c.Query("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from format, use RFC3339"})
			return
		}
		filter.From = t
	}

	if to := c.Query("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to format, use RFC3339"})
			return
		}
		filter.To = t
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