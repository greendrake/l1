package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/utils"

	"greendrake/l1/internal/auth" // For password hashing
	"greendrake/l1/internal/db"   // Added for retry mechanism
	"greendrake/l1/internal/models"
)

// ErrEmailExists is returned when an attempt is made to use an email that already exists.
var ErrEmailExists = errors.New("email already in use by another account")

// IUserService defines the interface for user-related operations.
// This allows for easier mocking in tests.
type IUserService interface {
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	CreatePhantomUser(ctx context.Context, email string) (*models.User, error)
	SetUserCredentials(ctx context.Context, userID utils.SixID, authType models.AuthType, password string) error
	FindByID(ctx context.Context, userID utils.SixID) (*models.User, error)
	GetAllActiveUserIDs(ctx context.Context) ([]utils.SixID, error)
	GetAllPhantomUserIDs(ctx context.Context) ([]utils.SixID, error)
	DeleteUserAndListings(ctx context.Context, userID utils.SixID) error
	SuspendUser(ctx context.Context, userIDToSuspend, adminUserID utils.SixID) error
	UnsuspendUser(ctx context.Context, userIDToUnsuspend utils.SixID) error
	RequestEmailChange(ctx context.Context, userID utils.SixID, newEmail string) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error)
	ApproveEmailChangeOld(ctx context.Context, userID utils.SixID) error
	ConfirmEmailChangeNew(ctx context.Context, userID utils.SixID) error
	FinalizeEmailChange(ctx context.Context, userID utils.SixID) error
	SetOTPSecret(ctx context.Context, userID utils.SixID, otpSecret string) error
	AddWebAuthnCredential(ctx context.Context, userID utils.SixID, cred models.WebAuthnCredential) error
	RemoveWebAuthnCredential(ctx context.Context, userID utils.SixID, credentialID string) error
	SetLinkedActionService(las ILinkedActionService)
	// Add other method signatures here...
	// FindByID(ctx context.Context, userID utils.SixID) (*models.User, error)
}

const usersCollection = "users"

// userService implements IUserService.
// Keep the struct unexported if NewUserService is the only intended way to create it.
type userService struct {
	db              *mongo.Database
	linkedActionSvc ILinkedActionService // Add dependency
	// cfg *config.Config // Add config if needed for defaults
}

// NewUserService creates a new UserService.
// Inject ILinkedActionService
func NewUserService(db *mongo.Database, linkedActionSvc ILinkedActionService /*, cfg *config.Config */) IUserService { // Return interface type
	return &userService{db: db, linkedActionSvc: linkedActionSvc /*, cfg: cfg */}
}

// SetLinkedActionService allows setting the linkedActionSvc after initialization to break a cycle.
func (s *userService) SetLinkedActionService(las ILinkedActionService) {
	s.linkedActionSvc = las
}

// FindByEmail finds a non-deleted user by their email address.
// Returns the user and nil error if found.
// Returns nil and mongo.ErrNoDocuments if not found.
// Returns nil and other error for database issues.
func (s *userService) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	collection := s.db.Collection(usersCollection)
	filter := bson.M{"email": email, "deleted": false}

	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, mongo.ErrNoDocuments
		}
		return nil, fmt.Errorf("error finding user by email %s: %w", email, err)
	}
	return &user, nil
}

// CreatePhantomUser creates a new, non-activated user marked as phantom.
// This user needs to confirm email and set credentials later.
func (s *userService) CreatePhantomUser(ctx context.Context, email string) (*models.User, error) {
	collection := s.db.Collection(usersCollection)

	// Ensure email uniqueness among non-deleted users before inserting
	// This check prevents race conditions better than just relying on FindByEmail before calling Create
	count, err := collection.CountDocuments(ctx, bson.M{"email": email, "deleted": false})
	if err != nil {
		return nil, fmt.Errorf("error checking email uniqueness for %s: %w", email, err)
	}
	if count > 0 {
		// This case should ideally be handled by the caller checking FindByEmail first,
		// but we add defense here. Return a specific error?
		return nil, fmt.Errorf("user with email %s already exists", email) // Consider ErrEmailExists here
	}

	now := time.Now().UTC()
	var newUser *models.User
	// err is already declared above

	operation := func() error {
		newUser = &models.User{
			ID:        utils.NewSixID(), // ID generated on each attempt
			Email:     email,
			Phantom:   true,
			Activated: false,
			Suspended: false,
			IsAdmin:   false,
			Overdue:   false,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
			NotificationPreferences: &models.NotificationPreferences{
				Enquiry:           true,
				Offer:             true,
				UserSuspension:    true,
				ListingSuspension: true,
				InvoiceOverdue:    true,
			},
		}
		_, insertErr := collection.InsertOne(ctx, newUser)
		return insertErr
	}

	err = db.Try(operation)

	if err != nil {
		// Check if the error is due to the unique email index constraint
		// This is a simplistic check; a more robust way would be to inspect the error details further if possible,
		// or ensure IsMongoDuplicateKeyError can distinguish between _id and other unique index violations.
		if mongo.IsDuplicateKeyError(err) && strings.Contains(err.Error(), "email_1") { // Assuming default index name for email
			return nil, ErrEmailExists // Return a more specific error for email collision
		}
		userIDStr := "<unknown>"
		if newUser != nil {
			userIDStr = newUser.ID.String()
		}
		return nil, fmt.Errorf("error inserting new phantom user for %s (last attempted user ID: %s) after multiple retries: %w",
			email, userIDStr, err)
	}

	return newUser, nil
}

// SetUserCredentials updates the user's auth type and secrets (e.g., password hash).
// It also marks the user as activated and no longer phantom.
func (s *userService) SetUserCredentials(ctx context.Context, userID utils.SixID, authType models.AuthType, password string /* Add other secrets like OTP seed, WebAuthn data */) error {
	collection := s.db.Collection(usersCollection)

	var hashedPassword string
	var err error
	if password != "" {
		hashedPassword, err = auth.HashPassword(password)
		if err != nil {
			return fmt.Errorf("failed to hash password for user %s: %w", userID.String(), err)
		}
	}

	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"auth_type":  authType,
			"password":   hashedPassword, // Store hash
			"activated":  true,
			"phantom":    false,
			"updated_at": now,
			// TODO: Add fields for OTP secret, WebAuthn credentials etc. based on authType
		},
	}

	result, err := collection.UpdateByID(ctx, userID, update)
	if err != nil {
		return fmt.Errorf("error updating credentials for user %s: %w", userID.String(), err)
	}

	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments // Or a more specific error
	}

	fmt.Printf("Successfully set credentials and activated user: %s\n", userID.String())
	return nil
}

// FindByID finds a non-deleted user by their ID.
func (s *userService) FindByID(ctx context.Context, userID utils.SixID) (*models.User, error) {
	var user models.User
	collection := s.db.Collection(usersCollection)
	filter := bson.M{"_id": userID, "deleted": false}

	err := collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, mongo.ErrNoDocuments
		}
		return nil, fmt.Errorf("error finding user by ID %s: %w", userID.String(), err)
	}
	return &user, nil
}

// GetAllActiveUserIDs retrieves the ObjectIDs of all non-deleted, activated users.
func (s *userService) GetAllActiveUserIDs(ctx context.Context) ([]utils.SixID, error) {
	collection := s.db.Collection(usersCollection)
	filter := bson.M{
		"deleted":   false,
		"activated": true,
		"suspended": false, // Exclude suspended users from billing checks?
		"phantom":   false, // Exclude phantom users
	}
	// Only fetch the _id field
	opts := options.Find().SetProjection(bson.M{"_id": 1})

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query active user IDs: %w", err)
	}
	defer cursor.Close(ctx)

	var results []struct {
		ID utils.SixID `bson:"_id"`
	}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode active user IDs: %w", err)
	}

	ids := make([]utils.SixID, len(results))
	for i, res := range results {
		ids[i] = res.ID
	}

	return ids, nil
}

// GetAllPhantomUserIDs retrieves the ObjectIDs of all non-deleted phantom users.
func (s *userService) GetAllPhantomUserIDs(ctx context.Context) ([]utils.SixID, error) {
	collection := s.db.Collection(usersCollection)
	filter := bson.M{"deleted": false, "phantom": true}
	opts := options.Find().SetProjection(bson.M{"_id": 1})
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query phantom user IDs: %w", err)
	}
	defer cursor.Close(ctx)
	var results []struct {
		ID utils.SixID `bson:"_id"`
	}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode phantom user IDs: %w", err)
	}
	ids := make([]utils.SixID, len(results))
	for i, res := range results {
		ids[i] = res.ID
	}
	return ids, nil
}

// DeleteUserAndListings performs a soft delete on a user and all their listings.
func (s *userService) DeleteUserAndListings(ctx context.Context, userID utils.SixID) error {
	collection := s.db.Collection(usersCollection)
	now := time.Now().UTC()

	// Update user document
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"deleted":    true,
			"deleted_at": now,
			"updated_at": now,
		},
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error deleting user %s: %w", userID.String(), err)
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("user %s not found", userID.String())
	}

	// Update all user's listings
	listingsCollection := s.db.Collection(listingsCollection)
	listingFilter := bson.M{
		"user_id": userID,
		"deleted": false,
	}
	listingUpdate := bson.M{
		"$set": bson.M{
			"deleted":    true,
			"deleted_at": now,
			"updated_at": now,
		},
	}

	_, err = listingsCollection.UpdateMany(ctx, listingFilter, listingUpdate)
	if err != nil {
		return fmt.Errorf("db error deleting listings for user %s: %w", userID.String(), err)
	}

	return nil
}

// SuspendUser marks a user as suspended.
// Ensures an admin cannot suspend themselves.
func (s *userService) SuspendUser(ctx context.Context, userIDToSuspend, adminUserID utils.SixID) error {
	if userIDToSuspend == adminUserID {
		return fmt.Errorf("admin cannot suspend themselves")
	}
	collection := s.db.Collection(usersCollection)
	filter := bson.M{"_id": userIDToSuspend, "deleted": false}
	update := bson.M{"$set": bson.M{"suspended": true, "updated_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error suspending user %s: %w", userIDToSuspend.String(), err)
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments // User not found or already deleted
	}
	log.Printf("User %s suspended by admin %s", userIDToSuspend.String(), adminUserID.String())
	// TODO: Invalidate user's JWTs? Blueprint says no need.
	// TODO: Enqueue notification task to suspended user?
	return nil
}

// UnsuspendUser marks a user as not suspended.
func (s *userService) UnsuspendUser(ctx context.Context, userIDToUnsuspend utils.SixID) error {
	collection := s.db.Collection(usersCollection)
	filter := bson.M{"_id": userIDToUnsuspend, "deleted": false}
	update := bson.M{"$set": bson.M{"suspended": false, "updated_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error unsuspending user %s: %w", userIDToUnsuspend.String(), err)
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments // User not found or already deleted
	}
	log.Printf("User %s unsuspended", userIDToUnsuspend.String())
	return nil
}

// RequestEmailChange starts the email change process for a user.
// It updates the user doc and creates the necessary linked actions.
func (s *userService) RequestEmailChange(ctx context.Context, userID utils.SixID, newEmail string) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error) {
	// Check if newEmail is already in use by another user
	existingUser, findErr := s.FindByEmail(ctx, newEmail)
	if findErr != nil && !errors.Is(findErr, mongo.ErrNoDocuments) {
		return nil, nil, fmt.Errorf("database error checking new email: %w", findErr)
	}
	if existingUser != nil && existingUser.ID != userID {
		return nil, nil, ErrEmailExists
	}

	// 2. Fetch the current user to get their old email address
	currentUser, userErr := s.FindByID(ctx, userID)
	if userErr != nil {
		return nil, nil, fmt.Errorf("failed to fetch current user details for email change: %w", userErr)
	}
	oldEmailAddr := currentUser.Email // Define oldEmailAddr here

	collection := s.db.Collection(usersCollection)
	emailChange := &models.EmailChange{
		NewAddress:      newEmail,
		ApprovedFromOld: false,
		ConfirmedNew:    false,
	}
	update := bson.M{"$set": bson.M{"email_change": emailChange, "updated_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	if err != nil {
		err = fmt.Errorf("failed to update user doc for email change request: %w", err)
		return
	}
	if result.MatchedCount == 0 {
		err = mongo.ErrNoDocuments
		return
	}

	// Create the linked actions for old email approval and new email confirmation
	// Pass oldEmailAddr to CreateEmailChangeActions
	oldAction, newAction, err = s.linkedActionSvc.CreateEmailChangeActions(ctx, userID, oldEmailAddr, newEmail)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create email change linked actions: %w", err)
	}

	log.Printf("Initiated email change for user %s from %s to %s. OldAction: %s, NewAction: %s",
		userID.String(), oldEmailAddr, newEmail, oldAction.ID.String(), newAction.ID.String()) // Using Crockford Base32
	return
}

// ApproveEmailChangeOld marks the old email as approved.
func (s *userService) ApproveEmailChangeOld(ctx context.Context, userID utils.SixID) error {
	collection := s.db.Collection(usersCollection)
	update := bson.M{"$set": bson.M{"email_change.approved_from_old": true, "updated_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	// Attempt to finalize after successful approval
	finalizationErr := s.FinalizeEmailChange(ctx, userID)
	if finalizationErr != nil {
		// Log the finalization error but don't return it, as the approval itself succeeded
		log.Printf("User %s approved old email, but finalization check failed/not ready: %v", userID.String(), finalizationErr)
	}
	return nil // Return nil as the approval step was successful
}

// ConfirmEmailChangeNew marks the new email as confirmed.
func (s *userService) ConfirmEmailChangeNew(ctx context.Context, userID utils.SixID) error {
	collection := s.db.Collection(usersCollection)
	update := bson.M{"$set": bson.M{"email_change.confirmed_new": true, "updated_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	// Attempt to finalize after successful confirmation
	finalizationErr := s.FinalizeEmailChange(ctx, userID)
	if finalizationErr != nil {
		// Log the finalization error but don't return it, as the confirmation itself succeeded
		log.Printf("User %s confirmed new email, but finalization check failed/not ready: %v", userID.String(), finalizationErr)
	}
	return nil // Return nil as the confirmation step was successful
}

// FinalizeEmailChange updates the user's email and removes the email_change field if both steps are done.
func (s *userService) FinalizeEmailChange(ctx context.Context, userID utils.SixID) error {
	collection := s.db.Collection(usersCollection)
	var user models.User
	err := collection.FindOne(ctx, bson.M{"_id": userID, "deleted": false}).Decode(&user)
	if err != nil || user.EmailChange == nil {
		return mongo.ErrNoDocuments
	}
	if user.EmailChange.ApprovedFromOld && user.EmailChange.ConfirmedNew {
		update := bson.M{"$set": bson.M{"email": user.EmailChange.NewAddress, "updated_at": time.Now().UTC()}, "$unset": bson.M{"email_change": ""}}
		_, err := collection.UpdateOne(ctx, bson.M{"_id": userID}, update)
		return err
	}
	return fmt.Errorf("email change not fully confirmed")
}

func (s *userService) SetOTPSecret(ctx context.Context, userID utils.SixID, otpSecret string) error {
	collection := s.db.Collection(usersCollection)
	update := bson.M{"$set": bson.M{"otp_secret": otpSecret, "updated_at": time.Now().UTC()}}
	_, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	return err
}

func (s *userService) AddWebAuthnCredential(ctx context.Context, userID utils.SixID, cred models.WebAuthnCredential) error {
	collection := s.db.Collection(usersCollection)
	update := bson.M{"$push": bson.M{"webauthn_credentials": cred}, "$set": bson.M{"updated_at": time.Now().UTC()}}
	_, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	return err
}

func (s *userService) RemoveWebAuthnCredential(ctx context.Context, userID utils.SixID, credentialID string) error {
	collection := s.db.Collection(usersCollection)
	update := bson.M{"$pull": bson.M{"webauthn_credentials": bson.M{"credential_id": credentialID}}, "$set": bson.M{"updated_at": time.Now().UTC()}}
	_, err := collection.UpdateOne(ctx, bson.M{"_id": userID, "deleted": false}, update)
	return err
}

// TODO: Add other user service methods as needed:
// - FindByID
// - UpdateProfile (name, default settings, notifications)
// - RequestEmailChange (creates EmailChange field)
// - ApproveEmailChangeOld / ConfirmEmailChangeNew (updates EmailChange field)
// - FinalizeEmailChange (updates email, removes EmailChange field)
// - DeleteUser (sets deleted flag)
// - SuspendUser / UnsuspendUser
// - UpdateOverdueStatus
// - GetUserValidations etc.
