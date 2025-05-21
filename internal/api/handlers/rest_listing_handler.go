package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/utils"
)

// RestListingHandler handles REST requests for listings.
type RestListingHandler struct {
	listingService services.IListingService
	// userService    services.IUserService // Needed for /user/:id/listing
}

// NewRestListingHandler creates a new RestListingHandler.
func NewRestListingHandler(listingService services.IListingService /*, userService services.IUserService*/) *RestListingHandler {
	return &RestListingHandler{
		listingService: listingService,
		// userService:    userService,
	}
}

// SearchListings handles GET /v1/listing/search and GET /v1/listing/:country_code/search
func (h *RestListingHandler) SearchListings(c *gin.Context) {
	// Extract query parameters
	query := c.Query("q")
	tagsStr := c.Query("tags")
	limitStr := c.DefaultQuery("limit", "50")
	cursor := c.Query("cursor")
	sortBy := c.Query("sort")
	latStr := c.Query("lat")
	lonStr := c.Query("lon")
	distStr := c.Query("dist_km")

	// Country code from path parameter
	countryCodeParam := c.Param("country_code")
	var countryCode *string
	if countryCodeParam != "" {
		cc := strings.ToUpper(countryCodeParam)
		countryCode = &cc
	}

	// Parse limit
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 200 {
		limit = 50
	}

	// Parse tags (allow comma-separated, trim whitespace)
	var tags []string
	if tagsStr != "" {
		rawTags := strings.Split(tagsStr, ",")
		for _, tag := range rawTags {
			if trimmed := strings.TrimSpace(tag); trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	// Parse geo parameters
	var nearLocation *models.GeoJSON
	var maxDistanceKM *int // Use KM as input unit
	if latStr != "" && lonStr != "" {
		lat, latErr := strconv.ParseFloat(latStr, 64)
		lon, lonErr := strconv.ParseFloat(lonStr, 64)
		if latErr == nil && lonErr == nil {
			nearLocation = &models.GeoJSON{Type: "Point", Coordinates: []float64{lon, lat}}
			if distStr != "" {
				distKmVal, distErr := strconv.Atoi(distStr)
				if distErr == nil && distKmVal > 0 {
					maxDistanceKM = &distKmVal
				}
			}
		}
	}

	// Pointers for optional params
	var queryPtr *string
	if query != "" {
		queryPtr = &query
	}
	var cursorPtr *string
	if cursor != "" {
		cursorPtr = &cursor
	}

	// Call service
	listings, nextCursor, err := h.listingService.SearchListings(
		c.Request.Context(),
		queryPtr,
		countryCode,
		tags,
		nearLocation,
		maxDistanceKM, // Pass KM value
		limit,
		cursorPtr,
		sortBy,
	)

	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search listings"})
		return
	}

	// Return results with next cursor
	c.JSON(http.StatusOK, gin.H{
		"data":        listings,
		"next_cursor": nextCursor,
	})
}

// GetListingByID handles GET /v1/listing/:id
func (h *RestListingHandler) GetListingByID(c *gin.Context) {
	listingIDHex := c.Param("id")
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid listing ID format"})
		return
	}

	listing, err := h.listingService.FindListingByID(c.Request.Context(), listingID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Listing not found"})
		} else {
			_ = c.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve listing"})
		}
		return
	}

	// TODO: Handle Accept header for HTML
	c.JSON(http.StatusOK, listing)
}

// SearchUserListings handles GET /v1/user/:id/listing
func (h *RestListingHandler) SearchUserListings(c *gin.Context) {
	userIDHex := c.Param("id")
	userID, err := utils.ParseSixID(userIDHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Extract query parameters
	query := c.Query("q")
	tagsStr := c.Query("tags")
	limitStr := c.DefaultQuery("limit", "50")
	cursor := c.Query("cursor")
	sortBy := c.DefaultQuery("sort", "date_desc") // Default to date posted desc
	latStr := c.Query("lat")
	lonStr := c.Query("lon")
	distStr := c.Query("dist_km")

	// Parse limit
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 200 {
		limit = 50
	}

	// Parse tags
	var tags []string
	if tagsStr != "" {
		rawTags := strings.Split(tagsStr, ",")
		for _, tag := range rawTags {
			if trimmed := strings.TrimSpace(tag); trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	// Parse geo parameters
	var nearLocation *models.GeoJSON
	var maxDistanceKM *int
	if latStr != "" && lonStr != "" {
		lat, latErr := strconv.ParseFloat(latStr, 64)
		lon, lonErr := strconv.ParseFloat(lonStr, 64)
		if latErr == nil && lonErr == nil {
			nearLocation = &models.GeoJSON{Type: "Point", Coordinates: []float64{lon, lat}}
			if distStr != "" {
				distKmVal, distErr := strconv.Atoi(distStr)
				if distErr == nil && distKmVal > 0 {
					maxDistanceKM = &distKmVal
				}
			}
		}
	}

	// Pointers for optional params
	var queryPtr *string
	if query != "" {
		queryPtr = &query
	}
	var cursorPtr *string
	if cursor != "" {
		cursorPtr = &cursor
	}

	// Call service with user filter
	listings, nextCursor, err := h.listingService.SearchListingsByUser(
		c.Request.Context(),
		userID,
		queryPtr,
		tags,
		nearLocation,
		maxDistanceKM,
		limit,
		cursorPtr,
		sortBy,
	)

	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search user listings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":        listings,
		"next_cursor": nextCursor,
	})
}

func (h *RestListingHandler) GetUserListings(c *gin.Context) {
	userIDHex := c.Param("id")
	userID, err := utils.ParseSixID(userIDHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	ctx := c.Request.Context()
	listings, err := h.listingService.FindListingsByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found or suspended"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch listings"})
		}
		return
	}
	c.JSON(http.StatusOK, listings)
}

func RegisterRestListingRoutes(r *gin.Engine, handler *RestListingHandler) {
	r.GET("/v1/listing/:id", handler.GetListingByID)
	r.GET("/v1/listing/search", handler.SearchListings)
	r.GET("/v1/user/:id/listing", handler.SearchUserListings)
}
