package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"greendrake/l1/internal/auth"
)

const (
	// ContextKeyUserID holds the key for user ID in Gin context.
	ContextKeyUserID = "userID"
	// ContextKeyIsAdmin holds the key for admin status in Gin context.
	ContextKeyIsAdmin = "isAdmin"
)

// AuthMiddleware creates a Gin middleware for JWT authentication.
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			return
		}

		tokenString := parts[1]
		claims, err := auth.ValidateJWT(tokenString, jwtSecret)
		if err != nil {
			errMsg := fmt.Sprintf("Invalid or expired token: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errMsg})
			return
		}

		// // Optional: Check if user exists and is not suspended/deleted in DB?
		// // This adds DB lookup overhead to every authenticated request.
		// // The blueprint doesn't explicitly require this check per request after JWT validation.
		// // Let's assume valid JWT = valid session for now, unless issues arise.
		// db := c.MustGet("db").(*mongo.Database) // Need to pass DB via context
		// userService := services.NewUserService(db)
		// user, err := userService.FindByID(c.Request.Context(), claims.UserID)
		// if err != nil || user.Suspended || user.Deleted { ... Abort ... }

		// Set user info in context for handlers to use
		c.Set(ContextKeyUserID, claims.UserID) // Store as string (Hex representation)
		c.Set(ContextKeyIsAdmin, claims.IsAdmin)

		c.Next()
	}
}

// AdminMiddleware creates a Gin middleware to check for admin privileges.
// Assumes AuthMiddleware runs first.
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get(ContextKeyIsAdmin)
		if !exists || !isAdmin.(bool) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Administrator privileges required"})
			return
		}
		c.Next()
	}
}
