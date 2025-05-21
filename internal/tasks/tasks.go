package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg" // For encoding JPEG
	// "image/png"  // Removed - image.Decode handles it
	"io"
	"log"
	"net"
	"net/http" // Added for HTTP client
	"strings"
	"time" // Added

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hibiken/asynq"
	"github.com/nfnt/resize"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo" // Added
	"greendrake/l1/internal/utils"

	"greendrake/l1/internal/config"
	"greendrake/l1/internal/email"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/storage"
)

// TaskType defines the type of a background task.
const (
	TypeEmailDelivery = "email:deliver"
	TypeImageProcess  = "image:process"
	// Add other task types here...
	TypePhantomCleanup      = "user:phantom:cleanup"
	TypeInvoiceGenerate     = "billing:invoice:generate"
	TypeInvoiceCheckOverdue = "billing:invoice:check_overdue"
	TypeUserValidationCheck = "user:validation:check"
)

// --- Task Client (Enqueuing tasks) ---

func NewClient(rdb *redis.Client) *asynq.Client {
	clientOpt := asynq.RedisClientOpt{
		Addr: rdb.Options().Addr,
		// Add Password, DB if needed from rdb.Options()
	}
	return asynq.NewClient(clientOpt)
}

// --- Task Server (Processing tasks) ---

// TaskProcessor handles the processing of tasks.
// It holds dependencies needed by task handlers.
type TaskProcessor struct {
	cfg                   *config.Config
	emailSender           email.Sender
	storageService        storage.IS3Storage
	listingService        services.IListingService
	userValidationService services.IUserValidationService
	billingService        services.IBillingService
	configService         services.IConfigService
	userService           services.IUserService
	emailTemplateService  services.IEmailTemplateService
	s3Client              *s3.Client
	taskClient            *asynq.Client
}

func NewTaskProcessor(
	cfg *config.Config,
	emailSender email.Sender,
	storageService storage.IS3Storage,
	listingService services.IListingService,
	userValidationService services.IUserValidationService,
	billingService services.IBillingService,
	configService services.IConfigService,
	userService services.IUserService,
	emailTemplateService services.IEmailTemplateService,
	s3Client *s3.Client,
	taskClient *asynq.Client,
) *TaskProcessor {
	return &TaskProcessor{
		cfg:                   cfg,
		emailSender:           emailSender,
		storageService:        storageService,
		listingService:        listingService,
		userValidationService: userValidationService,
		billingService:        billingService,
		configService:         configService,
		userService:           userService,
		emailTemplateService:  emailTemplateService,
		s3Client:              s3Client,
		taskClient:            taskClient,
	}
}

// SetupServer configures and returns an Asynq server instance.
func SetupServer(rdb *redis.Client, processor *TaskProcessor, isImageWorker bool, isBgWorker bool) *asynq.Server {
	serverOpt := asynq.RedisClientOpt{
		Addr: rdb.Options().Addr,
		// Add Password, DB if needed
	}

	srv := asynq.NewServer(
		serverOpt,
		asynq.Config{
			// Specify different queues for different task types based on worker mode
			Queues: map[string]int{
				"critical": 6, // Example queue priorities
				"default":  3,
				"low":      1,
				"images":   5, // Separate queue for images
			},
			// Add other config options like Concurrency, ErrorHandler etc.
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				// Log the error
				fmt.Printf("[Asynq Error] Task Type: %s, Payload: %s, Error: %v\n", task.Type(), string(task.Payload()), err)
			}),
		},
	)

	// Register handlers based on worker type
	mux := asynq.NewServeMux()

	if isBgWorker { // Register handlers for the main background worker
		mux.HandleFunc(TypeEmailDelivery, processor.HandleEmailDeliveryTask)
		mux.HandleFunc(TypeUserValidationCheck, processor.HandleUserValidationCheckTask)
		mux.HandleFunc(TypeInvoiceGenerate, processor.HandleInvoiceGenerateTask)
		// Register other non-image background tasks...
		mux.HandleFunc(TypePhantomCleanup, processor.HandlePhantomCleanupTask)
		// mux.HandleFunc(TypeInvoiceCheckOverdue, processor.HandleInvoiceCheckOverdueTask)
		fmt.Println("Registered background task handlers (including images & validation & billing).")
	}

	if isImageWorker { // Register handlers for the image processing worker
		mux.HandleFunc(TypeImageProcess, processor.HandleImageProcessTask)
		fmt.Println("Registered image processing task handlers.")
	}

	if !isBgWorker && !isImageWorker {
		// API mode doesn't run a task server, but could potentially enqueue tasks
		fmt.Println("Running in API mode, no task server started.")
		return nil // Or return the server without starting it?
	}

	// Start the server with the configured mux
	if err := srv.Run(mux); err != nil {
		log.Fatalf("Could not run Asynq server: %v", err)
	}

	return srv
}

// --- Task Handlers ---

// HandleEmailDeliveryTask processes email delivery tasks.
type EmailTaskPayload struct {
	To         string                 `json:"to"`
	TemplateID string                 `json:"template_id"`
	Locale     string                 `json:"locale,omitempty"` // Optional locale
	Data       map[string]interface{} `json:"data"`
}

func (p *TaskProcessor) HandleEmailDeliveryTask(ctx context.Context, t *asynq.Task) error {
	var payload EmailTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal email task payload: %v: %w", err, asynq.SkipRetry)
	}

	fmt.Printf("Sending email task: To=%s, Template=%s\n", payload.To, payload.TemplateID)

	// Determine locale (use default if not provided)
	locale := payload.Locale
	if locale == "" {
		locale = "en-US" // TODO: Make default locale configurable?
	}

	// Get Email Template from DB
	tmpl, err := p.emailTemplateService.GetTemplate(ctx, payload.TemplateID, locale)
	if err != nil {
		log.Printf("Error getting email template %s/%s: %v", payload.TemplateID, locale, err)
		// Non-retryable if template not found
		return fmt.Errorf("email template not found: %w", asynq.SkipRetry)
	}

	// Simple placeholder replacement (replace {{.key}})
	// TODO: Use a proper templating engine (text/template, html/template) for safety and flexibility
	subjectRendered := tmpl.Subject
	bodyRendered := tmpl.Body
	for key, val := range payload.Data {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		valueStr := fmt.Sprintf("%v", val) // Basic string conversion
		subjectRendered = strings.ReplaceAll(subjectRendered, placeholder, valueStr)
		bodyRendered = strings.ReplaceAll(bodyRendered, placeholder, valueStr)
	}

	// Construct the raw email message including headers
	// This logic is moved here from the SMTPSender
	fromAddress := p.cfg.SmtpFromAddress // Get From address from TaskProcessor's config
	if fromAddress == "" {
		// Fallback, though config should ideally always provide this
		fromAddress = "noreply@example.com"
		log.Printf("Warning: SmtpFromAddress not configured, using fallback %s for email to %s", fromAddress, payload.To)
	}

	// Basic email structure with essential headers.
	// Note: Proper MIME encoding for HTML or attachments would be more complex.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("To: %s\r\n", payload.To))
	sb.WriteString(fmt.Sprintf("From: %s\r\n", fromAddress))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subjectRendered))
	sb.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	sb.WriteString("\r\n") // End of headers
	sb.WriteString(bodyRendered)
	sb.WriteString("\r\n") // Ensure body ends with CRLF if not already there

	rawMessage := []byte(sb.String())

	// Send using the new signature
	err = p.emailSender.Send(ctx, []string{payload.To}, subjectRendered, rawMessage)
	if err != nil {
		fmt.Printf("Email sending failed (will retry?): %v\n", err)
		return err
	}

	fmt.Printf("Email task processed successfully: To=%s, Template=%s\n", payload.To, payload.TemplateID)
	// TODO: Update Enquiry.Sent flag? Requires enquiryID in payload or separate task type.
	return nil
}

// HandleImageProcessTask processes image normalization tasks.
type ImageTaskPayload struct {
	S3Key     string `json:"s3_key"`
	ListingID string `json:"listing_id"`
}

func (p *TaskProcessor) HandleImageProcessTask(ctx context.Context, t *asynq.Task) error {
	var payload ImageTaskPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal image task payload: %v: %w", err, asynq.SkipRetry)
	}

	listingID, err := utils.ParseSixID(payload.ListingID)
	if err != nil {
		log.Printf("Invalid ListingID in image task payload: %s", payload.ListingID)
		return fmt.Errorf("invalid listing ID in payload: %w", asynq.SkipRetry)
	}

	log.Printf("Processing image task: S3Key=%s, ListingID=%s\n", payload.S3Key, payload.ListingID)

	// 1. Download image from S3
	getObjectOutput, err := p.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.cfg.AwsS3Bucket),
		Key:    aws.String(payload.S3Key),
	})
	if err != nil {
		log.Printf("Error getting object %s from S3: %v", payload.S3Key, err)
		// If object not found, maybe the upload failed? SkipRetry.
		// Use errors.As to check for specific AWS error types if needed.
		// For now, retry other errors.
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			log.Printf("S3 object %s not found, likely upload failed or key incorrect.", payload.S3Key)
			return fmt.Errorf("s3 object not found: %w", asynq.SkipRetry)
		}
		return fmt.Errorf("failed to download image from S3: %w", err)
	}
	defer getObjectOutput.Body.Close()

	imgData, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		log.Printf("Error reading image object body for key %s: %v", payload.S3Key, err)
		return fmt.Errorf("failed to read image data: %w", err)
	}

	// Check initial size before decoding (more efficient)
	maxSizeBytes := int64(p.cfg.ImageMaxSizeMB) * 1024 * 1024
	if int64(len(imgData)) > maxSizeBytes {
		log.Printf("Image %s exceeds max size (%d > %d bytes). Skipping.", payload.S3Key, len(imgData), maxSizeBytes)
		// TODO: Delete the oversized object from S3?
		// err = p.storageService.DeleteObject(ctx, payload.S3Key)
		return fmt.Errorf("image exceeds max size: %w", asynq.SkipRetry)
	}

	img, format, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		log.Printf("Error decoding image for key %s: %v", payload.S3Key, err)
		// TODO: Delete invalid image from S3?
		return fmt.Errorf("unsupported image format or corrupt image: %w", asynq.SkipRetry)
	}
	log.Printf("Decoded image %s, format: %s, size: %dx%d", payload.S3Key, format, img.Bounds().Dx(), img.Bounds().Dy())

	// 2. Check dimensions
	maxWidth := uint(p.cfg.ImageMaxDimension)
	maxHeight := uint(p.cfg.ImageMaxDimension)
	needsResize := uint(img.Bounds().Dx()) > maxWidth || uint(img.Bounds().Dy()) > maxHeight

	processedImageKey := payload.S3Key
	var processedImageData []byte
	contentType := *getObjectOutput.ContentType

	// 3. Resize if needed
	if needsResize {
		log.Printf("Resizing image %s (original: %dx%d, max: %dx%d)", payload.S3Key, img.Bounds().Dx(), img.Bounds().Dy(), maxWidth, maxHeight)
		resizedImg := resize.Thumbnail(maxWidth, maxHeight, img, resize.Lanczos3)
		var buf bytes.Buffer
		// Re-encode as JPEG (consider preserving original format if possible/needed)
		err = jpeg.Encode(&buf, resizedImg, &jpeg.Options{Quality: 85})
		if err != nil {
			log.Printf("Error encoding resized image %s: %v", payload.S3Key, err)
			return fmt.Errorf("failed to re-encode resized image: %w", err)
		}
		processedImageData = buf.Bytes()
		contentType = "image/jpeg" // Output is JPEG
		log.Printf("Resized image %s to %dx%d", payload.S3Key, resizedImg.Bounds().Dx(), resizedImg.Bounds().Dy())

		// Check size again after resizing/re-encoding
		if int64(len(processedImageData)) > maxSizeBytes {
			log.Printf("Resized image %s still exceeds max size (%d > %d bytes). Skipping.", payload.S3Key, len(processedImageData), maxSizeBytes)
			// TODO: Delete original object?
			return fmt.Errorf("resized image still exceeds max size: %w", asynq.SkipRetry)
		}

	} else {
		processedImageData = imgData
	}

	// 4. Upload processed image (overwrite original)
	_, err = p.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(p.cfg.AwsS3Bucket),
		Key:         aws.String(processedImageKey),
		Body:        bytes.NewReader(processedImageData),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		log.Printf("Error uploading processed image %s to S3: %v", processedImageKey, err)
		return fmt.Errorf("failed to upload processed image: %w", err)
	}

	// 5. Update Listing document
	err = p.listingService.AddImageToListing(ctx, listingID, processedImageKey)
	if err != nil {
		log.Printf("Error adding image key %s to listing %s: %v", processedImageKey, payload.ListingID, err)
		return fmt.Errorf("failed to update listing with processed image: %w", err)
	}

	log.Printf("Image task processed successfully: Key=%s, ListingID=%s", processedImageKey, payload.ListingID)
	return nil
}

// UserValidationCheckPayload defines the data for the validation check task.
type UserValidationCheckPayload struct {
	ValidationID string `json:"validation_id"`
}

// HandleUserValidationCheckTask checks domain/profile ownership.
func (p *TaskProcessor) HandleUserValidationCheckTask(ctx context.Context, t *asynq.Task) error {
	var payload UserValidationCheckPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal validation check payload: %v: %w", err, asynq.SkipRetry)
	}

	validationID, err := utils.ParseSixID(payload.ValidationID)
	if err != nil {
		log.Printf("Invalid ValidationID in check task payload: %s", payload.ValidationID)
		return fmt.Errorf("invalid validation ID in payload: %w", asynq.SkipRetry)
	}

	log.Printf("Checking validation ID: %s", payload.ValidationID)

	// 1. Fetch UserValidation document
	validation, err := p.userValidationService.GetValidationByID(ctx, validationID)
	if err != nil {
		log.Printf("Error fetching validation %s for check task: %v", payload.ValidationID, err)
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("validation not found: %w", asynq.SkipRetry)
		}
		return err
	}

	// Skip if already confirmed or revoked
	if validation.ConfirmedAt != nil || validation.RevokedAt != nil {
		log.Printf("Validation %s already confirmed or revoked. Skipping check.", payload.ValidationID)
		return nil
	}

	// 2. Fetch Validation Type for config (check_period)
	valType, err := p.userValidationService.GetValidationTypeByID(ctx, validation.TypeID)
	if err != nil {
		log.Printf("Error fetching validation type %s for validation %s: %v", validation.TypeID.String(), payload.ValidationID, err)
		return err
	}

	// 3. Perform Check
	found := false
	var checkErr error

	switch validation.ValidationType {
	case models.ValidationTypeDomainOwnership:
		domainName, ok := validation.Data["domain_name"].(string)
		if !ok {
			log.Printf("Missing or invalid domain_name in data for validation %s", payload.ValidationID)
			return fmt.Errorf("invalid validation data: %w", asynq.SkipRetry)
		}
		found, checkErr = checkDomainTXTRecord(domainName, validation.ValueToProve)

	case models.ValidationTypeOnlineProfile:
		profileURL, urlOk := validation.Data["profile_url"].(string)
		if !urlOk || profileURL == "" {
			log.Printf("Missing or invalid profile_url in data for validation %s", payload.ValidationID)
			return fmt.Errorf("invalid validation data: %w", asynq.SkipRetry)
		}
		found, checkErr = checkURLContent(ctx, profileURL, validation.ValueToProve)

	default:
		log.Printf("Unsupported validation type %s for validation %s", validation.ValidationType, payload.ValidationID)
		return fmt.Errorf("unsupported validation type: %w", asynq.SkipRetry)
	}

	if checkErr != nil {
		log.Printf("Check failed for validation %s: %v. Will retry later.", payload.ValidationID, checkErr)
		// Return the error itself to trigger default retry mechanism based on server config
		return checkErr
	}

	// 4. Confirm or Re-enqueue
	if found {
		err = p.userValidationService.ConfirmValidation(ctx, validationID)
		if err != nil {
			log.Printf("Error confirming validation %s: %v", payload.ValidationID, err)
			return err // Retry confirmation failure
		}
		log.Printf("Validation %s confirmed successfully!", payload.ValidationID)
		return nil // Confirmed, don't retry
	}

	// Not found yet, re-enqueue
	checkPeriodSec := 0.0 // Default to 0
	if periodVal, ok := valType.Config["check_period"]; ok {
		// Handle potential types from JSON/BSON (e.g., float64, int)
		switch v := periodVal.(type) {
		case float64:
			checkPeriodSec = v
		case int:
			checkPeriodSec = float64(v)
		case int32:
			checkPeriodSec = float64(v)
		case int64:
			checkPeriodSec = float64(v)
		default:
			log.Printf("Invalid type for check_period (%T) in config for validation type %s.", periodVal, validation.TypeID.String())
		}
	}

	if checkPeriodSec <= 0 {
		log.Printf("Invalid or missing check_period in config for validation type %s. Cannot re-enqueue check for %s.", validation.TypeID.String(), payload.ValidationID)
		return fmt.Errorf("missing or invalid check_period: %w", asynq.SkipRetry)
	}
	nextCheckDelay := time.Duration(checkPeriodSec) * time.Second

	taskInfo, err := p.taskClient.EnqueueContext(ctx, t, asynq.ProcessIn(nextCheckDelay))
	if err != nil {
		log.Printf("ERROR failed to re-enqueue validation check task for %s: %v", payload.ValidationID, err)
		return err
	}
	log.Printf("Validation %s not confirmed. Re-enqueued task %s to run in %v.", payload.ValidationID, taskInfo.ID, nextCheckDelay)
	return nil
}

// Helper function placeholder for DNS check
func checkDomainTXTRecord(domain, expectedValue string) (bool, error) {
	log.Printf("Checking TXT records for %s, looking for %s", domain, expectedValue)
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		// Handle DNS errors - some might be temporary
		log.Printf("DNS lookup error for %s: %v", domain, err)
		// Consider making certain DNS errors retryable
		return false, fmt.Errorf("dns lookup failed for %s: %w", domain, err)
	}
	for _, record := range txtRecords {
		if record == expectedValue {
			log.Printf("Found expected TXT record for %s!", domain)
			return true, nil
		}
	}
	log.Printf("Expected TXT record not found for %s", domain)
	return false, nil
}

// checkURLContent fetches a URL and checks if the body contains the expected value.
func checkURLContent(ctx context.Context, urlToCheck, expectedValue string) (bool, error) {
	log.Printf("Checking URL content for %s, looking for %s", urlToCheck, expectedValue)

	// Create an HTTP client with a timeout from context or a default
	client := http.Client{Timeout: 15 * time.Second} // Example timeout
	req, err := http.NewRequestWithContext(ctx, "GET", urlToCheck, nil)
	if err != nil {
		log.Printf("Error creating request for URL %s: %v", urlToCheck, err)
		return false, fmt.Errorf("failed to create request for %s: %w", urlToCheck, err)
	}
	// Add user agent? Some sites might block default Go client.
	req.Header.Set("User-Agent", "L1ValidationBot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching URL %s: %v", urlToCheck, err)
		// Consider making certain network errors retryable
		return false, fmt.Errorf("failed to fetch profile URL %s: %w", urlToCheck, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-OK status code %d fetching URL %s", resp.StatusCode, urlToCheck)
		// Consider 404 as non-retryable, others maybe retryable?
		return false, fmt.Errorf("received status %d for %s", resp.StatusCode, urlToCheck)
	}

	// Read the body (limit size to avoid memory issues?)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // Limit read to 1MB
	if err != nil {
		log.Printf("Error reading response body from %s: %v", urlToCheck, err)
		return false, fmt.Errorf("failed to read response body from %s: %w", urlToCheck, err)
	}

	if strings.Contains(string(bodyBytes), expectedValue) {
		log.Printf("Found expected value in content of %s!", urlToCheck)
		return true, nil
	}

	log.Printf("Expected value not found in content of %s", urlToCheck)
	return false, nil
}

// HandleInvoiceGenerateTask iterates through users and generates invoices if needed.
func (p *TaskProcessor) HandleInvoiceGenerateTask(ctx context.Context, t *asynq.Task) error {
	log.Println("Starting invoice generation task...")

	// TODO: Implement userService.GetAllActiveUserIDs
	userIDs, err := p.userService.GetAllActiveUserIDs(ctx) // Use injected service
	if err != nil {
		log.Printf("Error getting active user IDs for invoice generation: %v", err)
		return err // Retry?
	}
	// userIDs := []utils.SixID{}

	minInvoiceAmount := p.configService.GetFloat64(ctx, "MIN_INVOICE_AMOUNT", p.cfg.MinInvoiceAmount) // Use injected service
	generatedCount := 0

	for _, userID := range userIDs {
		chargeAmount, lineItems, err := p.billingService.CalculateChargesForUser(ctx, userID)
		if err != nil {
			log.Printf("Error calculating charges for user %s: %v. Skipping.", userID.String(), err)
			continue
		}

		if chargeAmount >= minInvoiceAmount {
			log.Printf("User %s has outstanding charges %.2f >= %.2f. Generating invoice...", userID.String(), chargeAmount, minInvoiceAmount)
			currencyCode := "USD" // TODO: Get default currency from config
			invoice, err := p.billingService.GenerateInvoice(ctx, userID, lineItems, chargeAmount, currencyCode)
			if err != nil {
				log.Printf("Error generating invoice for user %s: %v", userID.String(), err)
				continue
			}

			log.Printf("[TODO] Invoice %s generated for user %s. Need to enqueue email task.", invoice.ID.String(), userID.String())
			generatedCount++
		}
	}

	log.Printf("Invoice generation task finished. Generated %d invoices.", generatedCount)
	return nil
}

// HandlePhantomCleanupTask finds old phantom users and deletes them and their listings.
func (p *TaskProcessor) HandlePhantomCleanupTask(ctx context.Context, t *asynq.Task) error {
	log.Println("Starting phantom user cleanup task...")

	phantomUserIDs, err := p.userService.GetAllPhantomUserIDs(ctx)
	if err != nil {
		log.Printf("Error getting phantom user IDs: %v", err)
		return err // Retry DB error
	}

	if len(phantomUserIDs) == 0 {
		log.Println("No phantom users found to check.")
		return nil
	}

	maxAgeDuration := p.configService.GetDuration(ctx, "MAX_PHANTOM_AGE_SECONDS", p.cfg.MaxPhantomAge) // Needs GetDuration helper
	cutoffTime := time.Now().UTC().Add(-maxAgeDuration)
	deletedCount := 0

	log.Printf("Found %d phantom users. Checking against cutoff time %s", len(phantomUserIDs), cutoffTime.Format(time.RFC3339))

	for _, userID := range phantomUserIDs {
		// Find the user document to get their UpdatedAt
		user, err := p.userService.FindByID(ctx, userID)
		if err != nil {
			log.Printf("Error fetching phantom user %s during cleanup: %v. Skipping.", userID.String(), err)
			continue
		}

		// Find their most recent listing (if any)
		latestListing, err := p.listingService.FindLatestListingByUserID(ctx, userID)
		lastActivityTime := user.UpdatedAt // Default to user update time
		if err == nil && latestListing != nil {
			// If listing is newer, use its UpdatedAt
			if latestListing.UpdatedAt.After(lastActivityTime) {
				lastActivityTime = latestListing.UpdatedAt
			}
		} else if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			log.Printf("Error fetching latest listing for phantom user %s during cleanup: %v. Using user time.", userID.String(), err)
			// Continue check based on user time only
		}

		// Check if last activity is before the cutoff
		if lastActivityTime.Before(cutoffTime) {
			log.Printf("Phantom user %s last activity (%s) is before cutoff (%s). Deleting user and listings...",
				userID.String(), lastActivityTime.Format(time.RFC3339), cutoffTime.Format(time.RFC3339))
			if err := p.userService.DeleteUserAndListings(ctx, userID); err != nil {
				log.Printf("ERROR deleting phantom user %s and listings: %v", userID.String(), err)
				// Log error but continue to next user
			} else {
				deletedCount++
			}
		}
	}

	log.Printf("Phantom user cleanup finished. Deleted %d users.", deletedCount)
	return nil
}

// Add other task handlers here...
// func (p *TaskProcessor) HandlePhantomCleanupTask(ctx context.Context, t *asynq.Task) error { ... }
// func (p *TaskProcessor) HandleInvoiceCheckOverdueTask(ctx context.Context, t *asynq.Task) error { ... }
