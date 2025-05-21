package middleware

import (
	// "context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"greendrake/l1/internal/config"   // For default limits
	"greendrake/l1/internal/models"   // Added for APIType
	"greendrake/l1/internal/services" // For specific endpoint limits
)

// clientLimiter stores rate limiters for a specific client.
type clientLimiter struct {
	softLimiter *rate.Limiter
	hardLimiter *rate.Limiter
	lastSeen    time.Time
}

// RateLimiterMiddleware manages rate limiting for API endpoints.
type RateLimiterMiddleware struct {
	clients       map[string]*clientLimiter
	mu            sync.Mutex
	cfg           *config.Config          // For defaults
	configService services.IConfigService // For endpoint specific limits
}

// NewRateLimiterMiddleware creates a new RateLimiterMiddleware.
func NewRateLimiterMiddleware(cfg *config.Config, configService services.IConfigService) *RateLimiterMiddleware {
	rm := &RateLimiterMiddleware{
		clients:       make(map[string]*clientLimiter),
		cfg:           cfg,
		configService: configService,
	}
	// Start a background goroutine to clean up old client entries
	go rm.cleanupClients()
	return rm
}

// getClientIdentifier creates a unique key based on IP, Fingerprint, and SPA Session ID.
func getClientIdentifier(c *gin.Context) string {
	ip := c.ClientIP()
	fingerprint := c.GetHeader("X-BFP")
	spaSession := c.GetHeader("X-SPA")
	// Simple concatenation for now. Consider hashing for more robustness/anonymity.
	return fmt.Sprintf("%s|%s|%s", ip, fingerprint, spaSession)
}

// getClientLimiter retrieves or creates the rate limiters for a given client identifier.
func (rm *RateLimiterMiddleware) getClientLimiter(identifier string, softRate, softBurst int, hardRate, hardBurst int) *clientLimiter {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	limiter, exists := rm.clients[identifier]
	if !exists {
		limiter = &clientLimiter{
			softLimiter: rate.NewLimiter(rate.Limit(softRate), softBurst),
			hardLimiter: rate.NewLimiter(rate.Limit(hardRate), hardBurst),
		}
		rm.clients[identifier] = limiter
		log.Printf("Created new rate limiter entry for client: %s", identifier)
	}
	limiter.lastSeen = time.Now()
	return limiter
}

// cleanupClients periodically removes old client entries from the map.
func (rm *RateLimiterMiddleware) cleanupClients() {
	// Run cleanup periodically (e.g., every 10 minutes)
	for {
		time.Sleep(10 * time.Minute)
		rm.mu.Lock()
		count := 0
		for id, client := range rm.clients {
			// Remove if not seen for a while (e.g., 3 * cleanup interval)
			if time.Since(client.lastSeen) > 30*time.Minute {
				delete(rm.clients, id)
				count++
			}
		}
		rm.mu.Unlock()
		if count > 0 {
			log.Printf("Rate limiter cleanup removed %d old client entries.", count)
		}
	}
}

// Limit creates the Gin middleware handler.
func (rm *RateLimiterMiddleware) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Identify client
		clientKey := getClientIdentifier(c)

		// Determine API type and endpoint/method name
		apiType := models.APITypeREST
		endpointIdentifier := c.FullPath()
		if c.Request.Method == http.MethodPost && strings.HasSuffix(c.FullPath(), "/api") {
			// TODO: Better way to get JSON method for rate limiting config?
			// Maybe inspect a custom header or first few bytes of body if possible?
			// For now, apply default REST limits to POST /api as well.
		}

		// 2. Get endpoint-specific limits (always fetch guest config for rate limiter)
		apiCfg, err := rm.configService.GetAPIEndpointConfig(c.Request.Context(), apiType, endpointIdentifier, false) // Always use isAuthenticated = false
		if err != nil {
			log.Printf("Error fetching API config for %s %s (guest): %v. Using defaults.", apiType, endpointIdentifier, err)
		}

		// Use specific limits if found, otherwise use global defaults
		softRate := rm.cfg.RateLimitSoftRefillRate
		softBurst := rm.cfg.RateLimitSoftBucketSize
		hardRate := rm.cfg.RateLimitHardRefillRate
		hardBurst := rm.cfg.RateLimitHardBucketSize

		if apiCfg != nil {
			if apiCfg.RateLimitSoft != nil {
				softRate = apiCfg.RateLimitSoft.TokenRefillRate
				softBurst = apiCfg.RateLimitSoft.BucketSize
			}
			if apiCfg.RateLimitHard != nil {
				hardRate = apiCfg.RateLimitHard.TokenRefillRate
				hardBurst = apiCfg.RateLimitHard.BucketSize
			}
		}

		// 3. Get/Create limiters for this client
		limiter := rm.getClientLimiter(clientKey, softRate, softBurst, hardRate, hardBurst)

		// 4. Check hard limit
		if !limiter.hardLimiter.Allow() {
			log.Printf("Hard rate limit exceeded for client: %s on %s %s", clientKey, apiType, endpointIdentifier)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		// 5. Check if CaptchaMiddleware verified the client as human
		isHuman := c.GetBool(ContextKeyIsHumanVerified) // Use context value set by CaptchaMiddleware

		// 6. Check soft limit only if not validated as human
		if !isHuman && !limiter.softLimiter.Allow() {
			log.Printf("Soft rate limit exceeded for client: %s on %s %s (captcha required)", clientKey, apiType, endpointIdentifier)
			c.AbortWithStatusJSON(http.StatusTeapot, gin.H{"error": "Captcha validation required"})
			return
		}

		c.Next()
	}
}
