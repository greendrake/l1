package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application.
type Config struct {
	// Environment
	RunMode string // Set via flag, not env

	// MongoDB
	MongoURI    string
	MongoDbName string

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// JWT
	JwtSecret       string
	JwtTTL          time.Duration
	CaptchaTokenTTL time.Duration

	// Server
	ApiPort        string
	ServiceApiPort string

	// Cloudflare
	CloudflareTurnstileSecretKey string
	CloudflareSiteVerifyURL      string

	// Billing
	FreeTierListings           int
	BasePeriodDays             int
	BaseRate                   float64
	MinInvoiceAmount           float64
	InvoicePaymentWaitTimeDays int
	MinOverduePeriodDays       int

	// Email
	SmtpHost        string
	SmtpPort        int
	SmtpUsername    string
	SmtpPassword    string
	SmtpFromAddress string
	EmailChangeTTL  time.Duration

	// AWS S3
	AwsAccessKeyID     string
	AwsSecretAccessKey string
	AwsRegion          string
	AwsS3Bucket        string
	ImageBaseS3URL     string
	ImageMaxDimension  int
	ImageMaxSizeMB     int

	// App Defaults
	AppName                 string
	PasswordRegexp          string
	MaxPhantomAge           time.Duration
	GetCacheTTL             time.Duration
	MaxNewTagsByUserPerHour int
	LoginToSetupTTL         time.Duration
	ResetAccessLinkTTL      time.Duration
	ObscureEncode           bool

	// Rate Limiting Defaults
	RateLimitSoftBucketSize int
	RateLimitSoftRefillRate int // tokens per second
	RateLimitHardBucketSize int
	RateLimitHardRefillRate int // tokens per second
}

// Load configuration from environment variables.
// RunMode needs to be passed in as it comes from command-line flags.
func Load(runMode string) (*Config, error) {
	// Load .env file, ignoring errors if it doesn't exist
	godotenv.Load()

	cfg := &Config{
		RunMode: runMode, // Set from flag
	}

	var err error

	// Helper function to get env var or default
	getEnv := func(key, defaultValue string) string {
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		return defaultValue
	}

	// Helper function to get required env var
	getRequiredEnv := func(key string) (string, error) {
		value, exists := os.LookupEnv(key)
		if !exists {
			return "", fmt.Errorf("missing required environment variable: %s", key)
		}
		return value, nil
	}

	// Load basic string values
	cfg.MongoURI, err = getRequiredEnv("MONGO_URI")
	if err != nil {
		return nil, err
	}
	cfg.MongoDbName = getEnv("MONGO_DB_NAME", "")
	cfg.RedisAddr = getEnv("REDIS_ADDR", "localhost:6379")
	cfg.RedisPassword = getEnv("REDIS_PASSWORD", "")
	cfg.JwtSecret, err = getRequiredEnv("JWT_SECRET")
	if err != nil {
		return nil, err
	}
	cfg.ApiPort = getEnv("API_PORT", "8080")
	cfg.ServiceApiPort = getEnv("SERVICE_API_PORT", "12345")
	cfg.CloudflareTurnstileSecretKey = getEnv("CLOUDFLARE_TURNSTILE_SECRET_KEY", "")
	cfg.CloudflareSiteVerifyURL = getEnv("CLOUDFLARE_SITEVERIFY_URL", "https://challenges.cloudflare.com/turnstile/v0/siteverify")
	cfg.SmtpHost = getEnv("SMTP_HOST", "")
	cfg.SmtpUsername = getEnv("SMTP_USERNAME", "")
	cfg.SmtpPassword = getEnv("SMTP_PASSWORD", "")
	cfg.SmtpFromAddress = getEnv("SMTP_FROM_ADDRESS", "noreply@l1.example.com")
	cfg.AwsAccessKeyID = getEnv("AWS_ACCESS_KEY_ID", "")
	cfg.AwsSecretAccessKey = getEnv("AWS_SECRET_ACCESS_KEY", "")
	cfg.AwsRegion = getEnv("AWS_REGION", "")
	cfg.AwsS3Bucket = getEnv("AWS_S3_BUCKET", "")
	cfg.ImageBaseS3URL = getEnv("IMAGE_BASE_S3_URL", "")
	cfg.AppName = getEnv("APP_NAME", "L1")
	cfg.PasswordRegexp = getEnv("PASSWORD_REGEXP", "^.{8,}$")

	// Load numeric and time duration values with defaults and parsing
	cfg.RedisDB, err = strconv.Atoi(getEnv("REDIS_DB", "0"))
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_DB: %w", err)
	}

	jwtTTLSeconds, err := strconv.ParseInt(getEnv("JWT_TTL_SECONDS", "3600"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_TTL_SECONDS: %w", err)
	}
	cfg.JwtTTL = time.Duration(jwtTTLSeconds) * time.Second

	captchaTTLSeconds, err := strconv.ParseInt(getEnv("CAPTCHA_TOKEN_TTL", "1200"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid CAPTCHA_TOKEN_TTL: %w", err)
	}
	cfg.CaptchaTokenTTL = time.Duration(captchaTTLSeconds) * time.Second

	cfg.SmtpPort, err = strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	cfg.FreeTierListings, err = strconv.Atoi(getEnv("FREE_TIER_LISTINGS", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid FREE_TIER_LISTINGS: %w", err)
	}

	cfg.BasePeriodDays, err = strconv.Atoi(getEnv("BASE_PERIOD_DAYS", "30"))
	if err != nil {
		return nil, fmt.Errorf("invalid BASE_PERIOD_DAYS: %w", err)
	}

	cfg.BaseRate, err = strconv.ParseFloat(getEnv("BASE_RATE", "1.00"), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid BASE_RATE: %w", err)
	}

	cfg.MinInvoiceAmount, err = strconv.ParseFloat(getEnv("MIN_INVOICE_AMOUNT", "10.00"), 64)
	if err != nil {
		return nil, fmt.Errorf("invalid MIN_INVOICE_AMOUNT: %w", err)
	}

	cfg.InvoicePaymentWaitTimeDays, err = strconv.Atoi(getEnv("INVOICE_PAYMENT_WAIT_TIME_DAYS", "14"))
	if err != nil {
		return nil, fmt.Errorf("invalid INVOICE_PAYMENT_WAIT_TIME_DAYS: %w", err)
	}

	cfg.MinOverduePeriodDays, err = strconv.Atoi(getEnv("MIN_OVERDUE_PERIOD_DAYS", "7"))
	if err != nil {
		return nil, fmt.Errorf("invalid MIN_OVERDUE_PERIOD_DAYS: %w", err)
	}

	cfg.ImageMaxDimension, err = strconv.Atoi(getEnv("IMAGE_MAX_DIMENSION", "2048"))
	if err != nil {
		return nil, fmt.Errorf("invalid IMAGE_MAX_DIMENSION: %w", err)
	}

	cfg.ImageMaxSizeMB, err = strconv.Atoi(getEnv("IMAGE_MAX_SIZE_MB", "10"))
	if err != nil {
		return nil, fmt.Errorf("invalid IMAGE_MAX_SIZE_MB: %w", err)
	}

	maxPhantomAgeSeconds, err := strconv.ParseInt(getEnv("MAX_PHANTOM_AGE_SECONDS", "172800"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_PHANTOM_AGE_SECONDS: %w", err)
	}
	cfg.MaxPhantomAge = time.Duration(maxPhantomAgeSeconds) * time.Second

	getCacheTTLSeconds, err := strconv.ParseInt(getEnv("GET_CACHE_TTL_SECONDS", "60"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GET_CACHE_TTL_SECONDS: %w", err)
	}
	cfg.GetCacheTTL = time.Duration(getCacheTTLSeconds) * time.Second

	cfg.MaxNewTagsByUserPerHour, err = strconv.Atoi(getEnv("MAX_NEW_TAGS_BY_USER_PER_HOUR", "10"))
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_NEW_TAGS_BY_USER_PER_HOUR: %w", err)
	}

	loginToSetupTTLSeconds, err := strconv.ParseInt(getEnv("LOGIN_TO_SETUP_TTL_SECONDS", "86400"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid LOGIN_TO_SETUP_TTL_SECONDS: %w", err)
	}
	cfg.LoginToSetupTTL = time.Duration(loginToSetupTTLSeconds) * time.Second

	resetAccessLinkTTLMinutes, err := strconv.ParseInt(getEnv("RESET_ACCESS_LINK_TTL_MINUTES", "20"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid RESET_ACCESS_LINK_TTL_MINUTES: %w", err)
	}
	cfg.ResetAccessLinkTTL = time.Duration(resetAccessLinkTTLMinutes) * time.Minute

	emailChangeTTLHours, err := strconv.ParseInt(getEnv("EMAIL_CHANGE_TTL_HOURS", "24"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid EMAIL_CHANGE_TTL_HOURS: %w", err)
	}
	cfg.EmailChangeTTL = time.Duration(emailChangeTTLHours) * time.Hour

	// Rate Limiting
	cfg.RateLimitSoftBucketSize, err = strconv.Atoi(getEnv("RATE_LIMIT_SOFT_BUCKET_SIZE", "2"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_SOFT_BUCKET_SIZE: %w", err)
	}
	cfg.RateLimitSoftRefillRate, err = strconv.Atoi(getEnv("RATE_LIMIT_SOFT_REFILL_RATE", "1"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_SOFT_REFILL_RATE: %w", err)
	}
	cfg.RateLimitHardBucketSize, err = strconv.Atoi(getEnv("RATE_LIMIT_HARD_BUCKET_SIZE", "8"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_HARD_BUCKET_SIZE: %w", err)
	}
	cfg.RateLimitHardRefillRate, err = strconv.Atoi(getEnv("RATE_LIMIT_HARD_REFILL_RATE", "4"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_HARD_REFILL_RATE: %w", err)
	}

	// TODO: Add loading logic for configuration stored in MongoDB once DB connection is established.
	// This initial load only covers environment variables. The blueprint requires dynamic config loading from DB.

	return cfg, nil
}
