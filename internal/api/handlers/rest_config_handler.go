package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"greendrake/l1/internal/services"
)

// RestConfigHandler handles requests for the /config REST endpoint.
type RestConfigHandler struct {
	configService services.IConfigService
}

// NewRestConfigHandler creates a new RestConfigHandler.
func NewRestConfigHandler(configService services.IConfigService) *RestConfigHandler {
	return &RestConfigHandler{configService: configService}
}

// GetPublicConfig returns the publicly accessible configuration parameters.
// Handles GET /v1/config
func (h *RestConfigHandler) GetPublicConfig(c *gin.Context) {
	publicConfig, err := h.configService.GetAllPublic(c.Request.Context())
	if err != nil {
		// Log the error
		_ = c.Error(err) // Attach error to context for potential logging middleware
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve configuration"})
		return
	}

	// TODO: Handle Accept header for HTML vs JSON response as per blueprint
	// For now, always return JSON
	c.JSON(http.StatusOK, publicConfig)
}
