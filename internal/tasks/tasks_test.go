package tasks_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"greendrake/l1/internal/config"
	// "greendrake/l1/internal/email"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/tasks"
)

// --- Mocks ---

// MockEmailSender
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	args := m.Called(ctx, to, subject, rawMessage)
	return args.Error(0)
}

// MockEmailTemplateService
type MockEmailTemplateService struct {
	mock.Mock
}

func (m *MockEmailTemplateService) GetTemplate(ctx context.Context, templateID, locale string) (*models.EmailTemplate, error) {
	args := m.Called(ctx, templateID, locale)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailTemplate), args.Error(1)
}

// --- Tests ---

func TestHandleEmailDeliveryTask_Success(t *testing.T) {
	mockEmailSender := new(MockEmailSender)
	mockTmplService := new(MockEmailTemplateService)
	cfg := &config.Config{} // Provide minimal config if needed

	// Task processor dependencies (only need email and template service for this task)
	p := tasks.NewTaskProcessor(cfg, mockEmailSender, nil, nil, nil, nil, nil, nil, mockTmplService, nil, nil)

	payloadData := map[string]interface{}{
		"name": "Tester",
		"link": "http://example.com/activate/123",
	}
	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         "test@example.com",
		TemplateID: "activate_account",
		Locale:     "en-US",
		Data:       payloadData,
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)

	// Mock expectations
	expectedTemplate := &models.EmailTemplate{
		Subject: "Welcome {{.name}}!",
		Body:    "Please activate: {{.link}}",
	}
	mockTmplService.On("GetTemplate", mock.Anything, "activate_account", "en-US").Return(expectedTemplate, nil)

	expectedTo := "test@example.com"
	expectedSubject := "Welcome Tester!"
	expectedBody := "Please activate: http://example.com/activate/123"

	// Expect Send to be called. Use a custom matcher for rawMessage to check its content.
	mockEmailSender.On("Send",
		mock.Anything,        // for context
		[]string{expectedTo}, // for to
		expectedSubject,      // for subject
		mock.MatchedBy(func(rawMsg []byte) bool { // for rawMessage
			msgStr := string(rawMsg)
			assert.Contains(t, msgStr, fmt.Sprintf("To: %s", expectedTo), "Raw message should contain To address")
			// From address check depends on cfg.SmtpFromAddress used in HandleEmailDeliveryTask
			// If cfg.SmtpFromAddress is empty in test, HandleEmailDeliveryTask uses "noreply@example.com"
			// For this test, let's ensure cfg.SmtpFromAddress is set or check for the fallback.
			expectedFrom := cfg.SmtpFromAddress
			if expectedFrom == "" {
				expectedFrom = "noreply@example.com"
			}
			assert.Contains(t, msgStr, fmt.Sprintf("From: %s", expectedFrom), "Raw message should contain From address")
			assert.Contains(t, msgStr, fmt.Sprintf("Subject: %s", expectedSubject), "Raw message should contain Subject")
			assert.Contains(t, msgStr, expectedBody, "Raw message should contain expected body content")
			return true // If all asserts pass, the matcher returns true
		}),
	).Return(nil)

	// Execute
	err := p.HandleEmailDeliveryTask(context.Background(), task)

	// Assert
	assert.NoError(t, err)
	mockTmplService.AssertExpectations(t)
	mockEmailSender.AssertExpectations(t)
}

func TestHandleEmailDeliveryTask_TemplateNotFound(t *testing.T) {
	mockEmailSender := new(MockEmailSender)
	mockTmplService := new(MockEmailTemplateService)
	cfg := &config.Config{}
	p := tasks.NewTaskProcessor(cfg, mockEmailSender, nil, nil, nil, nil, nil, nil, mockTmplService, nil, nil)

	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         "test@example.com",
		TemplateID: "nonexistent_template",
		Locale:     "en-US",
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)

	mockTmplService.On("GetTemplate", mock.Anything, "nonexistent_template", "en-US").Return(nil, assert.AnError) // Return error

	err := p.HandleEmailDeliveryTask(context.Background(), task)

	assert.Error(t, err)
	// Check if error is marked as non-retryable using errors.Is
	assert.True(t, errors.Is(err, asynq.SkipRetry), "Error should be SkipRetry for template not found")
	mockTmplService.AssertExpectations(t)
	// AssertNotCalled needs to match the signature of the Send method
	mockEmailSender.AssertNotCalled(t, "Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
