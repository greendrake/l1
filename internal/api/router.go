package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	// "github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"

	"greendrake/l1/internal/api/handlers"
	"greendrake/l1/internal/api/middleware"
	"greendrake/l1/internal/captcha"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/storage"
	// Placeholder for middleware, etc.
	// "greendrake/l1/internal/api/middleware"
)

// SetupRouter configures and returns the main Gin engine.
func SetupRouter(cfg *config.Config, db *mongo.Database, rdb *redis.Client, taskClient handlers.IAsynqClient, configSvc services.IConfigService) *gin.Engine {
	// Initialize services needed by API handlers HERE
	// userService must be initialized before linkedActionService
	userService := services.NewUserService(db, nil) // Pass nil for linkedActionService initially
	linkedActionService := services.NewLinkedActionService(db, cfg, userService)
	// Now, update userService with the initialized linkedActionService
	userService.SetLinkedActionService(linkedActionService)

	listingService := services.NewListingService(db, cfg)
	enquiryService := services.NewEnquiryService(db, cfg)
	locationService := services.NewLocationService(db)
	s3StorageService, err := storage.NewS3Storage(cfg)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to initialize S3 storage for API: %v", err)
	}
	userValidationService := services.NewUserValidationService(db, cfg)
	billingService := services.NewBillingService(db, cfg, configSvc, listingService, userService)
	// EmailTemplateService likely not needed by API handlers directly

	// Initialize Captcha Verifier
	captchaVerifier := captcha.NewTurnstileVerifier(cfg)

	r := gin.Default()

	// Initialize Middleware
	rateLimiter := middleware.NewRateLimiterMiddleware(cfg, configSvc)

	// Apply global middleware first (order matters)
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.CaptchaMiddleware(cfg, captchaVerifier))
	r.Use(rateLimiter.Limit())
	// TODO: Add Cloudflare Turnstile middleware

	// Initialize handlers
	jsonApiHandler := handlers.NewJsonApiHandler(
		cfg, db, rdb, taskClient, userService, linkedActionService, listingService, s3StorageService, enquiryService, userValidationService, billingService)
	restConfigHandler := handlers.NewRestConfigHandler(configSvc)
	restLocationHandler := handlers.NewRestLocationHandler(locationService)
	restListingHandler := handlers.NewRestListingHandler(listingService)
	restUserHandler := handlers.NewRestUserHandler(userService)

	v1 := r.Group("/v1")
	{
		// Public Routes (Rate limiting already applied globally)
		v1.POST("/api", jsonApiHandler.HandleRequest)
		v1.GET("/config", restConfigHandler.GetPublicConfig)

		// Location routes
		v1.GET("/location/search", restLocationHandler.SearchLocations)
		v1.GET("/location/:country_code/search", restLocationHandler.SearchLocations)

		// Listing routes - make them more specific to avoid conflicts
		v1.GET("/listing/search", restListingHandler.SearchListings)
		v1.GET("/listing/search/:country_code", restListingHandler.SearchListings)
		v1.GET("/listing/:id", restListingHandler.GetListingByID)

		// User routes
		v1.GET("/user/:id", restUserHandler.GetUserByID)
		v1.GET("/user/:id/listing", restListingHandler.SearchUserListings)

		v1.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})

		// Authenticated Routes (already have rate limiting from global middleware)
		authRequired := v1.Group("/")
		authRequired.Use(middleware.AuthMiddleware(cfg.JwtSecret))
		{
			// Example: authRequired.GET("/profile", profileHandler.GetProfile)
		}

		// Admin Routes (already have rate limiting from global middleware)
		adminRequired := v1.Group("/admin")
		adminRequired.Use(middleware.AuthMiddleware(cfg.JwtSecret), middleware.AdminMiddleware())
		{
			// Example: adminRequired.POST("/users/:id/suspend", adminHandler.SuspendUser)
		}
	}

	// --- Authenticated Routes ---
	// authGroup := v1.Group("/")
	// authGroup.Use(middleware.AuthMiddleware(cfg.JwtSecret))
	// {
	//    // Authenticated JSON API methods are handled within jsonApiHandler based on JWT presence
	//    // Add authenticated REST endpoints if any
	// }

	// --- Admin Routes ---
	// adminGroup := v1.Group("/admin") // Or adjust path as needed
	// adminGroup.Use(middleware.AuthMiddleware(cfg.JwtSecret), middleware.AdminMiddleware())
	// {
	//    // Admin JSON API methods are handled within jsonApiHandler based on JWT claims
	//    // Add admin REST endpoints if any
	// }

	return r
}

// SetupServiceRouter configures and returns the service Gin engine.
// Now requires Redis client for getTestEmail endpoint.
func SetupServiceRouter(cfg *config.Config, rdb *redis.Client, shutdownChan chan<- struct{}) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.POST("/api", func(c *gin.Context) {
		var req struct {
			Method    string          `json:"method"`
			Arguments json.RawMessage `json:"arguments"` // Use RawMessage
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request format"})
			return
		}

		switch req.Method {
		case "shutdown":
			fmt.Println("Received shutdown command via Service API")
			c.JSON(http.StatusOK, gin.H{"success": true, "result": "Shutdown initiated"})
			select {
			case shutdownChan <- struct{}{}:
				fmt.Println("Shutdown signal sent successfully.")
			default:
				fmt.Println("Shutdown channel already signaled or blocked.")
			}
		case "getTestEmail":
			var args []string // Expect ["action_type", "email"]
			if err := json.Unmarshal(req.Arguments, &args); err != nil || len(args) != 2 {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid arguments: expected JSON array [actionType, email]"})
				return
			}
			actionType := args[0]
			emailAddr := args[1]
			redisKey := fmt.Sprintf("mockemail:%s:%s", emailAddr, actionType)

			// Poll Redis briefly for the key
			var emailJsonData string
			var getErr error
			found := false
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second) // Short timeout for service call
			defer cancel()
			for i := 0; i < 10; i++ { // Poll up to ~2 seconds
				emailJsonData, getErr = rdb.Get(ctx, redisKey).Result()
				if getErr == nil {
					found = true
					rdb.Del(ctx, redisKey) // Delete after fetching
					break
				}
				if getErr != redis.Nil {
					log.Printf("Service API: Error getting key %s from Redis: %v", redisKey, getErr)
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Redis error"})
					return
				}
				// If redis.Nil, wait and retry
				time.Sleep(200 * time.Millisecond)
			}

			if !found {
				c.JSON(http.StatusNotFound, gin.H{"success": false, "error": fmt.Sprintf("Test email not found in Redis for key %s", redisKey)})
				return
			}

			// Unmarshal the found JSON data
			var emailData map[string]interface{}
			if err := json.Unmarshal([]byte(emailJsonData), &emailData); err != nil {
				log.Printf("Service API: Error unmarshalling email data from key %s: %v", redisKey, err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to parse stored email data"})
				return
			}

			// Return the full email data object
			c.JSON(http.StatusOK, gin.H{"success": true, "data": emailData})

		default:
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": fmt.Sprintf("Unknown service method: %s", req.Method)})
		}
	})
	return r
}
