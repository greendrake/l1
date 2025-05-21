package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware sets the necessary CORS headers.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Make allowed origin configurable (e.g., via ConfigService or env var)
		c.Header("Access-Control-Allow-Origin", "*") // Allow all for now, restrict in production
		c.Header("Access-Control-Allow-Credentials", "true")
		// Allowed headers based on blueprint
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-BFP, X-SPA, X-C-V, X-C-T")
		// Exposed headers based on blueprint
		c.Header("Access-Control-Expose-Headers", "X-C-T")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE") // Allow standard methods + PUT/DELETE if needed later

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
