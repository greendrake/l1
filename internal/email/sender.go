package email

import (
	"context"
	"fmt"
	"log"
	"net/smtp"

	"greendrake/l1/internal/config"
)

// Sender defines the interface for sending emails.
// The rawMessage parameter should contain the full email message, including headers and body, properly formatted.
type Sender interface {
	Send(ctx context.Context, to []string, subject string, rawMessage []byte) error
}

// SMTPSender implements the Sender interface using Go's net/smtp package.
type SMTPSender struct {
	cfg  *config.Config
	auth smtp.Auth
	addr string
}

// NewSMTPSender creates a new SMTPSender.
// It returns Sender so we can easily swap implementations (e.g., for testing).
func NewSMTPSender(cfg *config.Config) Sender {
	if cfg.SmtpHost == "" { // If no SMTP host configured, use a mock/logging sender
		log.Println("SMTP host not configured, using logging email sender.")
		// LoggingSender will also need to adapt to the new Send signature or be refactored.
		// For now, we'll focus on the main path. Consider LoggingSender needs an update.
		return &LoggingSender{cfg: cfg} // Pass cfg to LoggingSender if it needs FromAddress
	}

	// Setup SMTP authentication
	auth := smtp.PlainAuth(
		"", // identity
		cfg.SmtpUsername,
		cfg.SmtpPassword,
		cfg.SmtpHost,
	)
	addr := fmt.Sprintf("%s:%d", cfg.SmtpHost, cfg.SmtpPort)

	return &SMTPSender{
		cfg:  cfg,
		auth: auth,
		addr: addr,
	}
}

// Send sends an email using SMTP.
// The rawMessage is expected to be the complete email content.
func (s *SMTPSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	// rawMessage already contains all necessary headers and body.
	err := smtp.SendMail(s.addr, s.auth, s.cfg.SmtpFromAddress, to, rawMessage)
	if err != nil {
		log.Printf("Failed to send email via SMTP to %v: %v", to, err)
		return fmt.Errorf("smtp error: %w", err)
	}
	log.Printf("Email sent successfully via SMTP to %v (Subject: %s)", to, subject)
	return nil
}

// LoggingSender is a mock implementation that just logs email details.
// Useful for development or when SMTP isn't configured.
type LoggingSender struct {
	cfg *config.Config // Added to potentially access FromAddress if needed for logs
}

// Send logs the email details instead of sending.
// It now also logs the raw message content.
func (s *LoggingSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	log.Printf("--- Sending Email (Logged) ---")
	log.Printf("To: %v", to)
	// From address is part of rawMessage, but we can log the configured one for reference
	log.Printf("Configured From: %s", s.cfg.SmtpFromAddress)
	log.Printf("Subject: %s", subject) // Subject is also in rawMessage, but good for quick log glance
	log.Println("--- Raw Message ---")
	log.Println(string(rawMessage))
	log.Println("--- End Email ---")
	return nil
}
