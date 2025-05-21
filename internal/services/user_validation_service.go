package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// IUserValidationService defines the interface for user validation operations.
type IUserValidationService interface {
	GetValidationTypes(ctx context.Context) ([]models.UserValidationType, error)
	GetValidationTypeByID(ctx context.Context, typeID utils.SixID) (*models.UserValidationType, error)
	GetValidationByID(ctx context.Context, validationID utils.SixID) (*models.UserValidation, error)
	CreateDomainValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, domainName string) (*models.UserValidation, error)
	CreateOnlineProfileValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, profileID string) (*models.UserValidation, error)
	ConfirmValidation(ctx context.Context, validationID utils.SixID) error
	// CreateOnlineProfileValidation(...) error
	// CheckAndConfirmValidation(ctx context.Context, validationID utils.SixID) error
	// GetUserValidations(ctx context.Context, userID utils.SixID) ([]models.UserValidation, error)
}

const (
	validationTypesCollection = "user_validation_types"
	validationsCollection     = "user_validations"
)

// userValidationService implements IUserValidationService.
type userValidationService struct {
	db  *mongo.Database
	cfg *config.Config // Needed for APP_NAME to generate ValueToProve
}

// NewUserValidationService creates a new UserValidationService.
func NewUserValidationService(db *mongo.Database, cfg *config.Config) IUserValidationService {
	return &userValidationService{db: db, cfg: cfg}
}

// GetValidationTypes retrieves all available validation types.
func (s *userValidationService) GetValidationTypes(ctx context.Context) ([]models.UserValidationType, error) {
	collection := s.db.Collection(validationTypesCollection)
	filter := bson.M{} // Add filter if needed (e.g., {deleted: false})
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query validation types: %w", err)
	}
	defer cursor.Close(ctx)

	var types []models.UserValidationType
	if err = cursor.All(ctx, &types); err != nil {
		return nil, fmt.Errorf("failed to decode validation types: %w", err)
	}
	return types, nil
}

// GetValidationTypeByID retrieves a specific validation type by its ID.
func (s *userValidationService) GetValidationTypeByID(ctx context.Context, typeID utils.SixID) (*models.UserValidationType, error) {
	var valType models.UserValidationType
	collection := s.db.Collection(validationTypesCollection)
	filter := bson.M{"_id": typeID}
	err := collection.FindOne(ctx, filter).Decode(&valType)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("validation type %s not found", typeID.String())
		}
		return nil, fmt.Errorf("error finding validation type %s: %w", typeID.String(), err)
	}
	return &valType, nil
}

// GetValidationByID retrieves a specific validation by its ID.
func (s *userValidationService) GetValidationByID(ctx context.Context, validationID utils.SixID) (*models.UserValidation, error) {
	var validation models.UserValidation
	collection := s.db.Collection(validationsCollection)
	filter := bson.M{"_id": validationID, "deleted": false}
	err := collection.FindOne(ctx, filter).Decode(&validation)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("validation %s not found", validationID.String())
		}
		return nil, fmt.Errorf("error finding validation %s: %w", validationID.String(), err)
	}
	// Regenerate ValueToProve as it's not stored in DB
	validation.ValueToProve = fmt.Sprintf("%s:ACCOUNT_VALIDATION:%s", s.cfg.AppName, validation.ID.String())
	return &validation, nil
}

// CreateDomainValidation creates a pending domain validation entry.
func (s *userValidationService) CreateDomainValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, domainName string) (*models.UserValidation, error) {
	// 1. Validate typeID corresponds to a DomainOwnership type?
	valType, err := s.GetValidationTypeByID(ctx, typeID)
	if err != nil {
		return nil, err // Propagate error from GetValidationTypeByID
	}
	if valType.Type != models.ValidationTypeDomainOwnership {
		return nil, fmt.Errorf("validation type %s is not for domain ownership", typeID.String())
	}
	// TODO: Validate domainName format?

	// 2. Create the validation document
	collection := s.db.Collection(validationsCollection)
	now := time.Now().UTC()

	var newValidation *models.UserValidation
	// err is already declared above

	operation := func() error {
		validationID := utils.NewSixID() // ID generated on each attempt
		valueToProve := fmt.Sprintf("%s:ACCOUNT_VALIDATION:%s", s.cfg.AppName, validationID.String())
		newValidation = &models.UserValidation{
			ID:             validationID,
			UserID:         userID,
			TypeID:         typeID,
			ValidationType: valType.Type, // Denormalize
			Data: map[string]interface{}{
				"domain_name": domainName,
			},
			ValueToProve: valueToProve, // Store this temporarily?
			ConfirmedAt:  nil,
			RevokedAt:    nil,
			CreatedAt:    now,
			UpdatedAt:    now,
			Deleted:      false,
		}
		_, insertErr := collection.InsertOne(ctx, newValidation)
		return insertErr
	}

	err = db.Try(operation)

	if err != nil {
		validationIDStr := "<unknown>"
		if newValidation != nil {
			validationIDStr = newValidation.ID.String()
		}
		return nil, fmt.Errorf("failed to insert domain validation for user %s, domain %s (last attempted validation ID: %s) after multiple retries: %w",
			userID.String(), domainName, validationIDStr, err)
	}

	// 3. Enqueue the background check task (need task service integration)
	// taskPayload := tasks.UserValidationCheckPayload{ValidationID: validationID.String()}
	// task := asynq.NewTask(tasks.TypeUserValidationCheck, taskPayload, asynq.ProcessIn(checkDelay))
	// _, err = taskClient.Enqueue(task)
	fmt.Printf("[TODO] Domain validation %s created. Need to enqueue check task.", newValidation.ID.String()) // Use newValidation.ID here

	// Return the created validation object (ValueToProve might be useful for the user)
	return newValidation, nil
}

// CreateOnlineProfileValidation creates a pending online profile validation entry.
func (s *userValidationService) CreateOnlineProfileValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, profileID string) (*models.UserValidation, error) {
	// 1. Validate typeID corresponds to an OnlineProfile type
	valType, err := s.GetValidationTypeByID(ctx, typeID)
	if err != nil {
		return nil, err
	}
	if valType.Type != models.ValidationTypeOnlineProfile {
		return nil, fmt.Errorf("validation type %s is not for online profiles", typeID.String())
	}
	// TODO: Validate profileID based on type's config/schema?

	// 2. Create the validation document
	collection := s.db.Collection(validationsCollection)
	now := time.Now().UTC()

	var newValidation *models.UserValidation
	// err is already declared above

	operation := func() error {
		validationID := utils.NewSixID() // ID generated on each attempt
		valueToProve := fmt.Sprintf("%s:ACCOUNT_VALIDATION:%s", s.cfg.AppName, validationID.String())

		// Build profile URL from template (example only, needs safe template execution)
		urlTemplate, _ := valType.Config["url_template"].(string)
		profileURL := strings.Replace(urlTemplate, "{profile_id}", profileID, -1)

		newValidation = &models.UserValidation{
			ID:             validationID,
			UserID:         userID,
			TypeID:         typeID,
			ValidationType: valType.Type,
			Data: map[string]interface{}{
				"profile_id":  profileID,  // Store the ID used
				"profile_url": profileURL, // Store the derived URL
			},
			ValueToProve: valueToProve,
			ConfirmedAt:  nil,
			RevokedAt:    nil,
			CreatedAt:    now,
			UpdatedAt:    now,
			Deleted:      false,
		}
		_, insertErr := collection.InsertOne(ctx, newValidation)
		return insertErr
	}

	err = db.Try(operation)

	if err != nil {
		validationIDStr := "<unknown>"
		if newValidation != nil {
			validationIDStr = newValidation.ID.String()
		}
		return nil, fmt.Errorf("failed to insert online profile validation for user %s, profile %s (last attempted validation ID: %s) after multiple retries: %w",
			userID.String(), profileID, validationIDStr, err)
	}

	// 3. Enqueue background check task
	fmt.Printf("[TODO] Online profile validation %s created. Need to enqueue check task.", newValidation.ID.String()) // Use newValidation.ID here

	return newValidation, nil
}

// ConfirmValidation marks a validation as confirmed by setting ConfirmedAt.
func (s *userValidationService) ConfirmValidation(ctx context.Context, validationID utils.SixID) error {
	collection := s.db.Collection(validationsCollection)
	now := time.Now().UTC()
	filter := bson.M{
		"_id":          validationID,
		"confirmed_at": nil, // Only confirm if not already confirmed
		"revoked_at":   nil, // Cannot confirm if revoked
		"deleted":      false,
	}
	update := bson.M{
		"$set": bson.M{
			"confirmed_at": now,
			"updated_at":   now,
		},
	}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error confirming validation %s: %w", validationID.String(), err)
	}
	if result.MatchedCount == 0 {
		// Already confirmed, revoked, deleted, or not found
		return fmt.Errorf("validation %s not found or cannot be confirmed", validationID.String())
	}
	return nil
}

// TODO: Implement CheckAndConfirmValidation (used by background task)
// TODO: Implement GetUserValidations
