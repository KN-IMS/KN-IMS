package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/KGU-FIMS/Backend/internal"
)

// handleQueryEvents : GET /api/events
func (s *Server) handleQueryEvents(c *gin.Context) {
	filter := internal.EventFilter{
		AgentID:   c.Query("agent_id"),
		EventType: c.Query("type"),
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

	events, err := s.eventStore.QueryEvents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, events)
}