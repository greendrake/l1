package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/utils"
)

// RestUserHandler handles REST requests related to users.
type RestUserHandler struct {
	userService services.IUserService
	// listingService services.IListingService // Needed later for user listings count
}

// NewRestUserHandler creates a new RestUserHandler.
func NewRestUserHandler(userService services.IUserService /*, listingService services.IListingService*/) *RestUserHandler {
	return &RestUserHandler{
		userService: userService,
		// listingService: listingService,
	}
}

// PublicUser represents the data returned for a user profile.
type PublicUser struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DateJoined   string `json:"date_joined"` // Format? Just CreatedAt for now
	ListingCount int    `json:"listing_count"`
	Validations  []any  `json:"validations"` // TODO: Define Validation structure
}

// GetUserByID handles GET /v1/user/:id
func (h *RestUserHandler) GetUserByID(c *gin.Context) {
	userIDHex := c.Param("id")
	userID, err := utils.ParseSixID(userIDHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	user, err := h.userService.FindByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			_ = c.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		}
		return
	}

	// TODO: Get user's active listing count (needs ListingService method)
	listingCount := 0 // Placeholder
	// TODO: Get user's confirmed validations (needs ValidationService)
	validations := []any{} // Placeholder

	publicUser := PublicUser{
		ID:           user.ID.String(),
		Name:         user.Name,
		DateJoined:   user.CreatedAt.Format("2006-01-02"), // Example format
		ListingCount: listingCount,
		Validations:  validations,
	}

	// TODO: Handle Accept header for HTML
	c.JSON(http.StatusOK, publicUser)
}
