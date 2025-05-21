package services

import (
	"context"
	"fmt"
	"greendrake/l1/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Default email templates used as fallback when not found in database
var defaultEmailTemplates = map[string]models.EmailTemplate{
	"activate_account": {
		TemplateID: "activate_account",
		Locale:     "en-US",
		Subject:    "Activate your L1 Account",
		Body:       "Welcome! Please click here to activate: /la/{{.action_id}}",
	},
	"email_change_approve": {
		TemplateID: "email_change_approve",
		Locale:     "en-US",
		Subject:    "Approve Email Change Request",
		Body:       "Request to change email. Please click to approve from old address: /la/{{.action_id}}",
	},
	"email_change_confirm": {
		TemplateID: "email_change_confirm",
		Locale:     "en-US",
		Subject:    "Confirm New Email Address",
		Body:       "Please click here to confirm your new email address: /la/{{.action_id}}",
	},
	"email_login_code": {
		TemplateID: "email_login_code",
		Locale:     "en-US",
		Subject:    "Your L1 Login Code",
		Body:       "Here is your login code: {{.action_id}}. It will expire shortly. Alternatively, click /la/{{.action_id}}",
	},
	"confirm_account_deletion": {
		TemplateID: "confirm_account_deletion",
		Locale:     "en-US",
		Subject:    "Confirm Account Deletion",
		Body:       "Click here to confirm permanent deletion of your account: /la/{{.action_id}}",
	},
}

// IEmailTemplateService defines the interface for email template operations.
type IEmailTemplateService interface {
	GetTemplate(ctx context.Context, templateID, locale string) (*models.EmailTemplate, error)
}

const emailTemplatesCollection = "email_templates"

// EmailTemplateService handles operations related to email templates
type EmailTemplateService struct {
	db *mongo.Database
}

// NewEmailTemplateService creates a new instance of EmailTemplateService
func NewEmailTemplateService(db *mongo.Database) *EmailTemplateService {
	return &EmailTemplateService{
		db: db,
	}
}

// GetTemplate retrieves an email template by ID and locale
func (s *EmailTemplateService) GetTemplate(ctx context.Context, templateID string, locale string) (*models.EmailTemplate, error) {
	collection := s.db.Collection("email_templates")
	filter := bson.M{
		"template_id": templateID,
		"locale":      locale,
	}

	var template models.EmailTemplate
	err := collection.FindOne(ctx, filter).Decode(&template)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// If template not found in DB, try to get from defaults
			if defaultTemplate, ok := defaultEmailTemplates[templateID]; ok {
				return &defaultTemplate, nil
			}
			return nil, fmt.Errorf("template not found: %s (locale: %s)", templateID, locale)
		}
		return nil, fmt.Errorf("error retrieving template: %w", err)
	}

	return &template, nil
}

// SaveTemplate saves an email template to the database
func (s *EmailTemplateService) SaveTemplate(ctx context.Context, template *models.EmailTemplate) error {
	collection := s.db.Collection("email_templates")
	filter := bson.M{
		"template_id": template.TemplateID,
		"locale":      template.Locale,
	}

	update := bson.M{"$set": template}
	opts := options.Update().SetUpsert(true)

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("error saving template: %w", err)
	}

	return nil
}

// DeleteTemplate deletes an email template from the database
func (s *EmailTemplateService) DeleteTemplate(ctx context.Context, templateID string, locale string) error {
	collection := s.db.Collection("email_templates")
	filter := bson.M{
		"template_id": templateID,
		"locale":      locale,
	}

	_, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("error deleting template: %w", err)
	}

	return nil
}
