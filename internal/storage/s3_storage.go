package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"greendrake/l1/internal/config"
)

// IS3Storage defines the interface for S3 operations.
type IS3Storage interface {
	GeneratePresignedPutURL(ctx context.Context, userID, listingID, filename, contentType string) (string, string, error)
	// DeleteObject(ctx context.Context, key string) error
	// GetObjectMetadata(ctx context.Context, key string) (map[string]string, error)
}

// s3Storage implements IS3Storage.
type s3Storage struct {
	cfg           *config.Config
	s3Client      *s3.Client
	presignClient *s3.PresignClient
}

// NewS3Storage creates a new S3 storage service.
func NewS3Storage(cfg *config.Config) (IS3Storage, error) {
	awsCfg, err := aws_config.LoadDefaultConfig(context.TODO(),
		aws_config.WithRegion(cfg.AwsRegion),
		// Use static credentials from config for simplicity
		// For production, prefer IAM roles or other secure credential methods
		aws_config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AwsAccessKeyID,
			cfg.AwsSecretAccessKey,
			"", // session token
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(awsCfg)
	presignClient := s3.NewPresignClient(s3Client)

	return &s3Storage{
		cfg:           cfg,
		s3Client:      s3Client,
		presignClient: presignClient,
	}, nil
}

// GeneratePresignedPutURL creates a pre-signed URL for uploading an object.
// It returns the URL and the generated S3 object key.
func (s *s3Storage) GeneratePresignedPutURL(ctx context.Context, userID, listingID, filename, contentType string) (string, string, error) {
	// Generate a unique object key, perhaps including user/listing ID and a SixID
	// Example: uploads/user_<userID>/listing_<listingID>/<uuid>_<filename>
	// Ensure filename is sanitized to prevent path traversal or invalid characters.
	// For simplicity now, just use SixID + filename.
	objectKey := fmt.Sprintf("uploads/%s/%s/%s_%s", userID, listingID, uuid.NewString(), filename)

	// Set expiration for the pre-signed URL (e.g., 15 minutes)
	expiration := 15 * time.Minute

	presignParams := &s3.PutObjectInput{
		Bucket:      aws.String(s.cfg.AwsS3Bucket),
		Key:         aws.String(objectKey),
		ContentType: aws.String(contentType),
		// Add ACL if needed, e.g., aws.String("public-read") if images are public
		// Add Metadata if needed
	}

	presignedReq, err := s.presignClient.PresignPutObject(ctx, presignParams, s3.WithPresignExpires(expiration))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate presigned PUT URL for key %s: %w", objectKey, err)
	}

	fmt.Printf("Generated presigned URL for key: %s\n", objectKey)
	return presignedReq.URL, objectKey, nil
}

// Implement other IS3Storage methods...
