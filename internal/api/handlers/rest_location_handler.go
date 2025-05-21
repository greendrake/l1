package handlers

import (
	"net/http"
	"strconv"
	// "strings" // No longer directly needed here if FormatContext is used from models
	"strings" // Keep for strings.ToUpper

	"fmt"
	"github.com/gin-gonic/gin"
	"greendrake/l1/internal/models" // Added import
	"greendrake/l1/internal/services"
)

// RestLocationHandler handles requests for location REST endpoints.
type RestLocationHandler struct {
	locationService services.ILocationService
}

// NewRestLocationHandler creates a new RestLocationHandler.
func NewRestLocationHandler(locationService services.ILocationService) *RestLocationHandler {
	return &RestLocationHandler{locationService: locationService}
}

// SearchLocations handles GET /v1/location/search and GET /v1/location/:country_code/search
func (h *RestLocationHandler) SearchLocations(c *gin.Context) {
	query := c.Query("q") // Search query parameter
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing search query parameter 'q'"})
		return
	}

	limitStr := c.DefaultQuery("limit", "20") // Default limit
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 { // Add upper bound
		limit = 20
	}

	// Check if country code is provided in the path
	countryCodeParam := c.Param("country_code")
	var countryCode *string
	if countryCodeParam != "" {
		// TODO: Validate country code format (e.g., uppercase, 2 letters)?
		cc := strings.ToUpper(countryCodeParam)
		countryCode = &cc
	}

	locations, err := h.locationService.SearchLocations(c.Request.Context(), query, countryCode, limit)
	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search locations"})
		return
	}

	// Format results according to blueprint (append reversed context)
	results := make([]models.LocationAPIResponse, 0, len(locations))
	for _, loc := range locations {
		apiResponse := models.LocationAPIResponse{
			ID:          fmt.Sprintf("%d", loc.ID),
			Name:        loc.Name,
			Context:     models.FormatContext(loc.Context),
			CountryCode: loc.CountryCode,
		}
		if loc.Location != nil && loc.Location.Coordinates != nil {
			apiResponse.Coordinates = loc.Location.Coordinates
		}
		results = append(results, apiResponse)
	}

	// TODO: Handle Accept header for HTML response
	c.JSON(http.StatusOK, results)
}
