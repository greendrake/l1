package email

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"greendrake/l1/internal/config"
)

// FileEmailSender implements the Sender interface by writing email content to a file.
type FileEmailSender struct {
	filePath string
	// cfg is no longer strictly needed here if FromAddress is part of the rawMessage,
	// but keeping it for now in case of future use or if NewFileEmailSender needs it.
	cfg *config.Config
}

// NewFileEmailSender creates a new FileEmailSender.
// It ensures the directory for the log file exists.
func NewFileEmailSender(filePath string, cfg *config.Config) (Sender, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, fmt.Errorf("email log file path cannot be empty")
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for email log file '%s': %w", dir, err)
	}

	return &FileEmailSender{
		filePath: filePath,
		cfg:      cfg, // Keep cfg, might be useful for other metadata if needed
	}, nil
}

// Send writes the raw email message to the configured file.
func (s *FileEmailSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	timestamp := time.Now().Format(time.RFC3339Nano)

	// Open the file in append mode, create if it doesn't exist.
	file, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("FileEmailSender: Failed to open log file '%s': %v", s.filePath, err)
		return fmt.Errorf("failed to open email log file: %w", err)
	}
	defer file.Close()

	logEntryPrefix := fmt.Sprintf("--- Email Logged at %s (To: %v, Subject: %s) ---\n", timestamp, to, subject)
	logSuffix := "--- End Logged Email ---\n\n"

	fullLogEntry := []byte(logEntryPrefix)
	fullLogEntry = append(fullLogEntry, rawMessage...)
	fullLogEntry = append(fullLogEntry, []byte(logSuffix)...)

	if _, err := file.Write(fullLogEntry); err != nil {
		log.Printf("FileEmailSender: Failed to write to log file '%s': %v", s.filePath, err)
		return fmt.Errorf("failed to write email to log file: %w", err)
	}

	log.Printf("FileEmailSender: Email to %v (Subject: %s) logged to %s", to, subject, s.filePath)
	return nil
}
