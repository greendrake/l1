package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	// "github.com/gin-gonic/gin" // Unused
	"github.com/hibiken/asynq"
	// "github.com/redis/go-redis/v9" // Unused
	"greendrake/l1/internal/api"
	"greendrake/l1/internal/cache"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/email"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/storage"
	"greendrake/l1/internal/tasks"
	// "go.mongodb.org/mongo-driver/mongo" // Unused
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var runMode = flag.String("m", "all", "Run mode: 'api', 'bg' (background tasks), 'img' (image processing), 'all' (default)")

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*runMode)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Database
	mongoClient, mongoDb, err := db.ConnectDB(cfg.MongoURI, cfg.MongoDbName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.DisconnectDB(mongoClient); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		}
	}()

	// Initialize Cache (Redis)
	redisClient, err := cache.ConnectRedis(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer func() {
		if err := cache.DisconnectRedis(redisClient); err != nil {
			log.Printf("Error disconnecting from Redis: %v", err)
		}
	}()

	// Initialize S3 Client (needed by Task Processor)
	awsCfg, err := aws_config.LoadDefaultConfig(context.TODO(),
		aws_config.WithRegion(cfg.AwsRegion),
		aws_config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AwsAccessKeyID,
			cfg.AwsSecretAccessKey,
			"",
		)),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config for S3 client: %v", err)
	}
	s3Client := s3.NewFromConfig(awsCfg)

	// Initialize Email Sender
	var primaryEmailSender email.Sender
	if os.Getenv("MOCK_SERVICES") == "true" {
		log.Println("MOCK_SERVICES enabled: Using Redis email sender.")
		primaryEmailSender = email.NewRedisSender(redisClient, cfg)
	} else {
		log.Println("MOCK_SERVICES disabled or not set: Using SMTP/Logging email sender.")
		primaryEmailSender = email.NewSMTPSender(cfg)
	}

	// Setup Composite Email Sender
	// The composite sender will always include the primary sender.
	compositeSender := email.NewCompositeEmailSender(primaryEmailSender)

	// Optionally add FileEmailSender if LOG_EMAILS is set
	logEmailsPath := os.Getenv("LOG_EMAILS")
	if logEmailsPath != "" {
		log.Printf("LOG_EMAILS set to '%s', enabling file email logger.", logEmailsPath)
		fileSender, err := email.NewFileEmailSender(logEmailsPath, cfg)
		if err != nil {
			log.Printf("WARNING: Failed to initialize file email sender (LOG_EMAILS='%s'): %v. Proceeding without file logging.", logEmailsPath, err)
		} else {
			compositeSender.AddSender(fileSender)
			log.Println("File email logger added to composite sender.")
		}
	}

	// The emailSender passed to services will be the composite sender.
	finalEmailSender := email.Sender(compositeSender)

	// Initialize Services needed by handlers and/or task processor
	configSvc := services.NewConfigService(mongoDb, cfg, redisClient)
	userService := services.NewUserService(mongoDb, nil)
	linkedActionService := services.NewLinkedActionService(mongoDb, cfg, userService)
	userService.SetLinkedActionService(linkedActionService)

	listingService := services.NewListingService(mongoDb, cfg)
	s3StorageService, err := storage.NewS3Storage(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize S3 storage: %v", err)
	}
	// enquiryService is initialized within api.SetupRouter for the API handlers that need it.
	// enquiryService := services.NewEnquiryService(mongoDb, cfg)
	emailTemplateService := services.NewEmailTemplateService(mongoDb)
	userValidationService := services.NewUserValidationService(mongoDb, cfg)
	billingService := services.NewBillingService(mongoDb, cfg, configSvc, listingService, userService)

	// Initialize Task Client
	taskClient := tasks.NewClient(redisClient)

	// Initialize Task Processor
	taskProcessor := tasks.NewTaskProcessor(cfg, finalEmailSender, s3StorageService, listingService, userValidationService, billingService, configSvc, userService, emailTemplateService, s3Client, taskClient)

	// WaitGroup for managing goroutines
	var wg sync.WaitGroup

	// Channel to signal shutdown from Service API
	shutdownChan := make(chan struct{}, 1) // Buffered channel

	// Start Service API (always runs)
	// Inject redisClient for getTestEmail endpoint
	serviceRouter := api.SetupServiceRouter(cfg, redisClient, shutdownChan /* pass other dependencies */)
	serviceSrv := &http.Server{
		Addr:    ":" + cfg.ServiceApiPort,
		Handler: serviceRouter,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("Service API listening on :%s\n", cfg.ServiceApiPort)
		if err := serviceSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Service API ListenAndServe error: %v", err)
		}
		fmt.Println("Service API server stopped.")
	}()

	// --- Mode-specific servers ---
	var mainApiSrv *http.Server
	var backgroundTaskSrv *asynq.Server
	var imageTaskSrv *asynq.Server

	fmt.Printf("Starting application in '%s' mode...\n", cfg.RunMode)

	apiMode := func() {
		fmt.Println("Starting main API server...")
		// Router now initializes its own needed services
		mainApiRouter := api.SetupRouter(cfg, mongoDb, redisClient, taskClient, configSvc)
		mainApiSrv = &http.Server{
			Addr:    ":" + cfg.ApiPort,
			Handler: mainApiRouter,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("Main API listening on :%s\n", cfg.ApiPort)
			if err := mainApiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Main API ListenAndServe error: %v", err)
			}
			fmt.Println("Main API server stopped.")
		}()
	}

	bgMode := func() {
		fmt.Println("Starting background worker...")
		backgroundTaskSrv = tasks.SetupServer(redisClient, taskProcessor, false, true)
		if backgroundTaskSrv != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Println("Background task server starting...")
				if err := backgroundTaskSrv.Run(nil); err != nil {
					log.Fatalf("Background task server error: %v", err)
				}
				fmt.Println("Background task server stopped.")
			}()
		}
	}

	imgMode := func() {
		fmt.Println("Starting image processing worker...")
		imageTaskSrv = tasks.SetupServer(redisClient, taskProcessor, true, false)
		if imageTaskSrv != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Println("Image processing task server starting...")
				mux := asynq.NewServeMux()
				mux.HandleFunc(tasks.TypeImageProcess, taskProcessor.HandleImageProcessTask)
				if err := imageTaskSrv.Run(mux); err != nil {
					log.Fatalf("Image processing server error: %v", err)
				}
				fmt.Println("Image processing server stopped.")
			}()
		}
	}

	switch cfg.RunMode {
	case "api":
		apiMode()
	case "bg":
		bgMode()
	case "img":
		imgMode()
	case "all":
		apiMode()
		bgMode()
		imgMode()
	default:
		log.Fatalf("Invalid run mode specified in config: %s.", cfg.RunMode)
	}

	// --- Graceful Shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		fmt.Printf("\nReceived signal: %s. Shutting down gracefully...\n", sig)
	case <-shutdownChan: // Listen for shutdown signal from Service API
		fmt.Println("\nShutdown requested via Service API. Shutting down gracefully...")
	}

	// Create context with timeout for shutdown
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()

	// Shutdown servers
	fmt.Println("Shutting down Service API server...")
	if err := serviceSrv.Shutdown(ctxShutdown); err != nil {
		log.Printf("Service API server shutdown error: %v", err)
	}

	if mainApiSrv != nil {
		fmt.Println("Shutting down Main API server...")
		if err := mainApiSrv.Shutdown(ctxShutdown); err != nil {
			log.Printf("Main API server shutdown error: %v", err)
		}
	}

	if backgroundTaskSrv != nil {
		fmt.Println("Shutting down Background Task server...")
		backgroundTaskSrv.Shutdown()
	}
	if imageTaskSrv != nil {
		fmt.Println("Shutting down Image Processing server...")
		imageTaskSrv.Shutdown()
	}

	// Wait for all server goroutines to finish
	fmt.Println("Waiting for servers to stop...")
	wg.Wait()

	fmt.Println("Server gracefully stopped")
}

// Placeholder for the function previously in api/router.go
// SetupRouter is now defined in internal/api/router.go
// Placeholder Asynq server structs/interfaces for background tasks
// type BackgroundTaskServer interface { Start() error; Shutdown() }
