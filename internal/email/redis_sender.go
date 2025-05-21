package email

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
)

// RedisSender implements the Sender interface by storing emails in Redis
type RedisSender struct {
	client *redis.Client
	cfg    *config.Config
}

// NewRedisSender creates a new RedisSender
func NewRedisSender(client *redis.Client, cfg *config.Config) Sender {
	return &RedisSender{
		client: client,
		cfg:    cfg,
	}
}

// Send stores a representation of the email in Redis instead of sending it via SMTP.
// The rawMessage []byte is not directly stored in Redis to maintain the existing JSON structure,
// but it's received as per the Sender interface. The `to` parameter is now a slice.
func (s *RedisSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	// Extract action type from subject or body (from rawMessage) if possible for key differentiation
	// This is a heuristic and might need refinement based on actual email content
	bodyStr := string(rawMessage) // Convert raw message to string to search for body content
	actionType := "unknown"
	if strings.Contains(subject, "Activate") {
		actionType = string(models.ActionLoginToSetupAccount)
	} else if strings.Contains(subject, "Approve Email Change") {
		actionType = string(models.ActionEmailChangeOldApprove)
	} else if strings.Contains(subject, "Confirm New Email") {
		actionType = string(models.ActionEmailChangeNewConfirm)
	} else if strings.Contains(subject, "Login Code") {
		actionType = string(models.ActionEmailLoginCode)
	} else if strings.Contains(subject, "Confirm Account Deletion") {
		actionType = string(models.ActionConfirmAccountDeletion)
	}

	// For Redis, we typically deal with a single primary recipient for the mock key.
	// If `to` has multiple addresses, we'll use the first one for the key.
	primaryTo := ""
	if len(to) > 0 {
		primaryTo = to[0]
	}

	emailData := map[string]interface{}{
		"to":         strings.Join(to, ", "), // Store all recipients as a comma-separated string
		"from":       s.cfg.SmtpFromAddress,
		"subject":    subject,
		"body":       bodyStr, // Storing the full raw message as body for simplicity in mock
		"sent_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"actionType": actionType, // Include for potential debugging
	}

	jsonData, err := json.Marshal(emailData)
	if err != nil {
		return fmt.Errorf("failed to marshal email data: %w", err)
	}

	// Store as a simple String with TTL (e.g., 5 minutes)
	key := fmt.Sprintf("mockemail:%s:%s", primaryTo, actionType)
	ttl := 5 * time.Minute

	err = s.client.Set(ctx, key, jsonData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store email in Redis key '%s': %w", key, err)
	}

	log.Printf("Mock email stored in Redis key '%s' (TTL: %v, To: %s, Subject: %s)", key, ttl, strings.Join(to, ", "), subject)
	return nil
}
