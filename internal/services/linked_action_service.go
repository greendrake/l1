package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// ILinkedActionService defines the interface for managing linked actions.
type ILinkedActionService interface {
	CreateLoginToSetupAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)
	CreateResetAccessAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)
	FindAndValidateAction(ctx context.Context, actionIDHex string, expectedUserID *utils.SixID) (*models.LinkedAction, error)
	MarkActionExecuted(ctx context.Context, actionID utils.SixID) error
	CreateEmailChangeActions(ctx context.Context, userID utils.SixID, oldEmail, newEmail string) (*models.LinkedAction, *models.LinkedAction, error)
	FindPendingEmailChangeActions(ctx context.Context, userID utils.SixID) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error)
	CreateEmailLoginCodeAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)
	CreateConfirmAccountDeletionAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)
	FindByID(ctx context.Context, actionID utils.SixID) (*models.LinkedAction, error)
	// Add other action creation/management methods...
}

const linkedActionsCollection = "linked_actions"

// linkedActionService implements ILinkedActionService.
type linkedActionService struct {
	db          *mongo.Database
	cfg         *config.Config
	userService IUserService
}

// NewLinkedActionService creates a new LinkedActionService.
func NewLinkedActionService(db *mongo.Database, cfg *config.Config, userService IUserService) ILinkedActionService {
	return &linkedActionService{db: db, cfg: cfg, userService: userService}
}

// CreateLoginToSetupAction creates a new "login_to_setup_account" linked action.
func (s *linkedActionService) CreateLoginToSetupAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	return s.createAction(ctx, userID, models.ActionLoginToSetupAccount, s.cfg.LoginToSetupTTL, nil)
}

// CreateResetAccessAction creates a new action for resetting access (uses login_to_setup type but different TTL).
func (s *linkedActionService) CreateResetAccessAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	return s.createAction(ctx, userID, models.ActionLoginToSetupAccount, s.cfg.ResetAccessLinkTTL, nil)
}

// createAction is a helper to create different types of linked actions.
func (s *linkedActionService) createAction(ctx context.Context, userID utils.SixID, actionType models.LinkedActionType, ttl time.Duration, data map[string]interface{}) (*models.LinkedAction, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	doc, err := db.InsertOne(ctx, s.db.Collection(linkedActionsCollection), &models.LinkedAction{
		UserID:    userID,
		Type:      actionType,
		Data:      data,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Executed:  nil,
		Deleted:   false,
	})
	return doc.(*models.LinkedAction), err
}

// FindAndValidateAction finds and validates a linked action by ID.
// Checks expiry, execution status, deletion status, and optionally the user ID.
// actionIDStr is a Crockford Base32 (or legacy SixID format) representation of the SixID.
func (s *linkedActionService) FindAndValidateAction(ctx context.Context, actionIDStr string, expectedUserID *utils.SixID) (*models.LinkedAction, error) {
	actionID, err := utils.ParseSixID(actionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid action ID format")
	}

	collection := s.db.Collection(linkedActionsCollection)
	filter := bson.M{
		"_id":        actionID,
		"executed":   nil,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"deleted":    false,
	}

	if expectedUserID != nil {
		filter["user_id"] = *expectedUserID
	}

	var action models.LinkedAction
	err = collection.FindOne(ctx, filter).Decode(&action)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("action link is invalid, expired, or already used")
		}
		return nil, fmt.Errorf("database error validating action %s: %w", actionIDStr, err)
	}

	return &action, nil
}

// MarkActionExecuted marks a linked action as executed.
func (s *linkedActionService) MarkActionExecuted(ctx context.Context, actionID utils.SixID) error {
	collection := s.db.Collection(linkedActionsCollection)
	now := time.Now().UTC()
	update := bson.M{"$set": bson.M{"executed": now}}

	result, err := collection.UpdateByID(ctx, actionID, update)
	if err != nil {
		return fmt.Errorf("failed to mark action %s as executed: %w", actionID.String(), err)
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("action %s not found or already executed when trying to mark", actionID.String()) // Crockford Base32 ID
	}
	return nil
}

// CreateEmailChangeActions creates two linked actions for email change process:
// 1. email_change_old_approve - sent to current email for approval
// 2. email_change_new_confirm - sent to new email for confirmation
func (s *linkedActionService) CreateEmailChangeActions(ctx context.Context, userID utils.SixID, oldEmail, newEmail string) (*models.LinkedAction, *models.LinkedAction, error) {
	commonData := map[string]interface{}{
		"old_email": oldEmail,
		"new_email": newEmail,
	}

	// Create action for old email approval
	oldAction, err := s.createAction(ctx, userID, models.ActionEmailChangeOldApprove, s.cfg.EmailChangeTTL, commonData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create old email approval action: %w", err)
	}

	// Data for new action includes common data and the ID of the old action
	newActionData := map[string]interface{}{
		"old_email":     oldEmail,
		"new_email":     newEmail,
		"old_action_id": oldAction.ID.String(), // Stored as Crockford Base32
	}

	// Create action for new email confirmation
	newAction, err := s.createAction(ctx, userID, models.ActionEmailChangeNewConfirm, s.cfg.EmailChangeTTL, newActionData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new email confirmation action: %w", err)
	}

	return oldAction, newAction, nil
}

// CreateEmailLoginCodeAction creates a new linked action for one-off email login codes.
func (s *linkedActionService) CreateEmailLoginCodeAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	ttl := 5 * time.Minute
	return s.createAction(ctx, userID, models.ActionEmailLoginCode, ttl, nil)
}

// CreateConfirmAccountDeletionAction creates a linked action for confirming account deletion.
func (s *linkedActionService) CreateConfirmAccountDeletionAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	ttl := 1 * time.Hour
	return s.createAction(ctx, userID, models.ActionConfirmAccountDeletion, ttl, nil)
}

// FindPendingEmailChangeActions finds the unexecuted approve/confirm actions for a user's email change request.
func (s *linkedActionService) FindPendingEmailChangeActions(ctx context.Context, userID utils.SixID) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error) {
	collection := s.db.Collection(linkedActionsCollection)
	filter := bson.M{
		"user_id":  userID,
		"executed": nil,
		"type": bson.M{
			"$in": []models.LinkedActionType{
				models.ActionEmailChangeOldApprove,
				models.ActionEmailChangeNewConfirm,
			},
		},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"deleted":    false,
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		err = fmt.Errorf("error querying pending email change actions for user %s: %w", userID.String(), err)
		return
	}
	defer cursor.Close(ctx)

	foundOld := false
	foundNew := false
	for cursor.Next(ctx) {
		var action models.LinkedAction
		if decodeErr := cursor.Decode(&action); decodeErr != nil {
			err = fmt.Errorf("error decoding action for user %s: %w", userID.String(), decodeErr)
			return
		}
		if action.Type == models.ActionEmailChangeOldApprove {
			oldAction = &action
			foundOld = true
		} else if action.Type == models.ActionEmailChangeNewConfirm {
			newAction = &action
			foundNew = true
		}
		if foundOld && foundNew {
			break
		}
	}

	if err = cursor.Err(); err != nil {
		err = fmt.Errorf("cursor error reading pending email change actions for user %s: %w", userID.String(), err)
		return
	}

	if !foundOld || !foundNew {
		err = fmt.Errorf("could not find both pending email change actions for user %s (old:%t, new:%t)", userID.String(), foundOld, foundNew)
		if !foundOld && !foundNew {
			err = mongo.ErrNoDocuments
		}
	}

	return
}

// FindByID retrieves a linked action by its ID, regardless of its status.
func (s *linkedActionService) FindByID(ctx context.Context, actionID utils.SixID) (*models.LinkedAction, error) {
	collection := s.db.Collection(linkedActionsCollection)
	filter := bson.M{"_id": actionID}
	var action models.LinkedAction
	err := collection.FindOne(ctx, filter).Decode(&action)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("action with ID %s not found", actionID.String()) // Crockford Base32 ID
		}
		return nil, fmt.Errorf("database error finding action %s: %w", actionID.String(), err) // Crockford Base32 ID
	}
	return &action, nil
}

// Implement other ILinkedActionService methods here...

// TODO: Add methods for other action types (EmailChange, ResetAccess, EmailLoginCode)
// CreateEmailChangeActions(ctx context.Context, userID utils.SixID, newEmail string) (*models.LinkedAction, *models.LinkedAction, error)
// CreateResetAccessAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)
// CreateEmailLoginCodeAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error)

// TODO: Add background task logic or service method to clean up old/executed/deleted actions.
