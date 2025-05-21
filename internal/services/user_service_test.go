package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"errors"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
	"strings"
)

var testMongoURI string

func init() {
	// Get current file path
	_, filename, _, _ := runtime.Caller(0)
	// Try to load .env from project root (3 levels up from this file)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	if err := godotenv.Load(filepath.Join(projectRoot, ".env")); err != nil {
		// Try current directory as fallback
		godotenv.Load()
	}

	testMongoURI = os.Getenv("MONGO_URI_TEST")
	if testMongoURI == "" {
		panic("MONGO_URI_TEST environment variable is required for tests")
	}
}

func setupTestDB(t *testing.T, dbName string) *mongo.Database {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(testMongoURI))
	require.NoError(t, err, "Failed to connect to MongoDB")
	db := client.Database(dbName)
	// Clean up collections
	_ = db.Collection("users").Drop(context.Background())
	return db
}

// Mock ILinkedActionService for user service tests
type mockLinkedActionServiceForUserTest struct {
	mock.Mock
}

func (m *mockLinkedActionServiceForUserTest) CreateLoginToSetupAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *mockLinkedActionServiceForUserTest) CreateResetAccessAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *mockLinkedActionServiceForUserTest) FindAndValidateAction(ctx context.Context, actionIDStr string, expectedUserID *utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, actionIDStr, expectedUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *mockLinkedActionServiceForUserTest) MarkActionExecuted(ctx context.Context, actionID utils.SixID) error {
	args := m.Called(ctx, actionID)
	return args.Error(0)
}
func (m *mockLinkedActionServiceForUserTest) CreateEmailChangeActions(ctx context.Context, userID utils.SixID, oldEmail, newEmail string) (*models.LinkedAction, *models.LinkedAction, error) {
	args := m.Called(ctx, userID, oldEmail, newEmail)
	var la1, la2 *models.LinkedAction
	if args.Get(0) != nil {
		la1 = args.Get(0).(*models.LinkedAction)
	}
	if args.Get(1) != nil {
		la2 = args.Get(1).(*models.LinkedAction)
	}
	return la1, la2, args.Error(2)
}
func (m *mockLinkedActionServiceForUserTest) FindPendingEmailChangeActions(ctx context.Context, userID utils.SixID) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error) {
	args := m.Called(ctx, userID)
	if args.Get(0) != nil {
		oldAction = args.Get(0).(*models.LinkedAction)
	}
	if args.Get(1) != nil {
		newAction = args.Get(1).(*models.LinkedAction)
	}
	return oldAction, newAction, args.Error(2)
}
func (m *mockLinkedActionServiceForUserTest) CreateEmailLoginCodeAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *mockLinkedActionServiceForUserTest) CreateConfirmAccountDeletionAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *mockLinkedActionServiceForUserTest) FindByID(ctx context.Context, actionID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, actionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}

// --- Test Setup Helper ---
func setupUserServiceTest(t *testing.T) (*mongo.Database, *mockLinkedActionServiceForUserTest, IUserService, func()) {
	// Use a unique DB name per test suite or function to avoid parallel test interference
	dbName := fmt.Sprintf("testdb_user_service_%d", time.Now().UnixNano())
	db := setupTestDB(t, dbName) // Assuming setupTestDB remains for DB connection/cleanup
	mockLAS := new(mockLinkedActionServiceForUserTest)
	svc := NewUserService(db, mockLAS)

	// Define the cleanup function returned by setupTestDB
	cleanup := func() {
		client := db.Client()
		if err := db.Drop(context.Background()); err != nil {
			t.Logf("Failed to drop database %s: %v", dbName, err)
		}
		if err := client.Disconnect(context.Background()); err != nil {
			t.Logf("Failed to disconnect MongoDB client: %v", err)
		}
	}
	return db, mockLAS, svc, cleanup
}

// --- Tests ---
func TestUserService_CreateAndFind(t *testing.T) {
	_, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	email := "test@example.com"
	user, err := svc.CreatePhantomUser(context.Background(), email)
	assert.NoError(t, err)
	assert.Equal(t, email, user.Email)
	assert.True(t, user.Phantom)

	fetched, err := svc.FindByEmail(context.Background(), email)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, fetched.ID)

	fetchedByID, err := svc.FindByID(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, fetchedByID.Email)

	// Duplicate email
	_, err = svc.CreatePhantomUser(context.Background(), email)
	assert.Error(t, err)
}

func TestUserService_SetCredentials(t *testing.T) {
	_, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	email := "creds@example.com"
	user, _ := svc.CreatePhantomUser(context.Background(), email)
	err := svc.SetUserCredentials(context.Background(), user.ID, models.AuthTypePasswordOnly, "password123")
	assert.NoError(t, err)
	fetched, _ := svc.FindByID(context.Background(), user.ID)
	assert.False(t, fetched.Phantom)
	assert.True(t, fetched.Activated)
}

func TestUserService_EmailUniqueness(t *testing.T) {
	_, mockLAS, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	email := "test@example.com"
	user, _ := svc.CreatePhantomUser(context.Background(), email)

	newEmail := "new@example.com"
	// Mock the linked action service call needed by RequestEmailChange
	mockedOldAction := &models.LinkedAction{ID: utils.NewSixID()}
	mockedNewAction := &models.LinkedAction{ID: utils.NewSixID()}
	mockLAS.On("CreateEmailChangeActions", mock.Anything, user.ID, email, newEmail).Return(mockedOldAction, mockedNewAction, nil)

	// Request the change
	_, _, err := svc.RequestEmailChange(context.Background(), user.ID, newEmail)
	assert.NoError(t, err)
	fetched, _ := svc.FindByID(context.Background(), user.ID)
	require.NotNil(t, fetched.EmailChange) // Ensure EmailChange field exists
	assert.Equal(t, newEmail, fetched.EmailChange.NewAddress)

	// Approve Old (Implicitly calls Finalize - should not finalize yet)
	err = svc.ApproveEmailChangeOld(context.Background(), user.ID)
	assert.NoError(t, err)
	fetched, _ = svc.FindByID(context.Background(), user.ID)
	require.NotNil(t, fetched.EmailChange, "EmailChange should still exist after only old approval")
	assert.True(t, fetched.EmailChange.ApprovedFromOld)
	assert.False(t, fetched.EmailChange.ConfirmedNew)

	// Confirm New (Implicitly calls Finalize - SHOULD finalize now)
	err = svc.ConfirmEmailChangeNew(context.Background(), user.ID)
	assert.NoError(t, err)

	// Verify implicit finalization occurred
	fetched, _ = svc.FindByID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, newEmail, fetched.Email, "Email should be updated after implicit finalization")
	assert.Nil(t, fetched.EmailChange, "EmailChange field should be nil after implicit finalization")

	// Explicit finalize call (Should fail now because email_change field is gone)
	err = svc.FinalizeEmailChange(context.Background(), user.ID)
	assert.Error(t, err, "Explicit FinalizeEmailChange should fail after implicit finalization")
	// Check for specific error like ErrNoDocuments or the custom message
	assert.True(t, errors.Is(err, mongo.ErrNoDocuments) || strings.Contains(err.Error(), "email change not fully confirmed"), "Error should indicate missing field or not confirmed")

	mockLAS.AssertExpectations(t) // Ensure CreateEmailChangeActions was called by RequestEmailChange
}

func TestUserService_RequestEmailChange(t *testing.T) {
	_, mockLAS, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()

	// Create initial user
	user, err := svc.CreatePhantomUser(context.Background(), "old@example.com")
	require.NoError(t, err)

	newEmail := "new@example.com"
	// Mock the linked action service call
	mockedOldAction := &models.LinkedAction{ID: utils.NewSixID()}
	mockedNewAction := &models.LinkedAction{ID: utils.NewSixID()}
	mockLAS.On("CreateEmailChangeActions", mock.Anything, user.ID, user.Email, newEmail).Return(mockedOldAction, mockedNewAction, nil)

	// Call the method under test - expecting 3 return values now
	retOldAction, retNewAction, err := svc.RequestEmailChange(context.Background(), user.ID, newEmail)
	require.NoError(t, err)
	assert.NotNil(t, retOldAction)
	assert.NotNil(t, retNewAction)
	assert.Equal(t, mockedOldAction.ID, retOldAction.ID)
	assert.Equal(t, mockedNewAction.ID, retNewAction.ID)

	// Verify user document update
	updatedUser, err := svc.FindByID(context.Background(), user.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedUser.EmailChange)
	assert.Equal(t, newEmail, updatedUser.EmailChange.NewAddress)
	assert.False(t, updatedUser.EmailChange.ApprovedFromOld)
	assert.False(t, updatedUser.EmailChange.ConfirmedNew)
	mockLAS.AssertExpectations(t) // Verify mock was called
}

func TestUserService_ApproveEmailChangeOld(t *testing.T) {
	db, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	// setup user with email_change object
	user, initialEmailChange := setupUserWithEmailChange(t, db)
	initialEmailChange.ApprovedFromOld = false // Ensure it starts false
	initialEmailChange.ConfirmedNew = false    // New is not confirmed yet
	_, err := db.Collection("users").UpdateByID(context.Background(), user.ID, bson.M{"$set": bson.M{"email_change": initialEmailChange}})
	require.NoError(t, err)

	err = svc.ApproveEmailChangeOld(context.Background(), user.ID)
	require.NoError(t, err)

	// Verify user.EmailChange.ApprovedFromOld is true
	fetched, _ := svc.FindByID(context.Background(), user.ID)
	require.NotNil(t, fetched.EmailChange)
	assert.True(t, fetched.EmailChange.ApprovedFromOld)
	assert.False(t, fetched.EmailChange.ConfirmedNew)                 // Should remain false
	assert.NotEqual(t, fetched.EmailChange.NewAddress, fetched.Email) // Email should NOT be updated yet
}

func TestUserService_ConfirmEmailChangeNew(t *testing.T) {
	db, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	// setup user with email_change object (already approved old)
	user, initialEmailChange := setupUserWithEmailChange(t, db)
	initialEmailChange.ApprovedFromOld = true // Assume old already approved
	initialEmailChange.ConfirmedNew = false   // Ensure it starts false
	_, err := db.Collection("users").UpdateByID(context.Background(), user.ID, bson.M{"$set": bson.M{"email_change": initialEmailChange}})
	require.NoError(t, err)

	err = svc.ConfirmEmailChangeNew(context.Background(), user.ID)
	require.NoError(t, err)

	// Verify user.EmailChange.ConfirmedNew is true AND finalization occurred
	fetched, err := svc.FindByID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, initialEmailChange.NewAddress, fetched.Email) // Email should be updated
	assert.Nil(t, fetched.EmailChange)                            // email_change field should be removed
}

func TestUserService_SuspendUnsuspend(t *testing.T) {
	db, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	ctx := context.Background()
	admin := "admin@example.com"
	user := "user@example.com"
	adminUser, _ := svc.CreatePhantomUser(ctx, admin)
	userUser, _ := svc.CreatePhantomUser(ctx, user)
	adminUser.IsAdmin = true
	_, err := db.Collection("users").UpdateByID(ctx, adminUser.ID, bson.M{"$set": bson.M{"is_admin": true}})
	require.NoError(t, err)
	// Admin cannot suspend self
	err = svc.SuspendUser(ctx, adminUser.ID, adminUser.ID)
	assert.Error(t, err)
	// Admin suspends user
	err = svc.SuspendUser(ctx, userUser.ID, adminUser.ID)
	assert.NoError(t, err)
	fetched, _ := svc.FindByID(ctx, userUser.ID)
	assert.True(t, fetched.Suspended)
	// Unsuspend
	err = svc.UnsuspendUser(ctx, userUser.ID)
	assert.NoError(t, err)
	fetched, _ = svc.FindByID(ctx, userUser.ID)
	assert.False(t, fetched.Suspended)
}

func TestUserService_OTPAndWebAuthn(t *testing.T) {
	_, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	ctx := context.Background()
	user, _ := svc.CreatePhantomUser(ctx, "otpwa@example.com")
	err := svc.SetOTPSecret(ctx, user.ID, "otpsecret")
	assert.NoError(t, err)
	cred := models.WebAuthnCredential{
		CredentialID: "cid",
		PublicKey:    "pk",
	}
	err = svc.AddWebAuthnCredential(ctx, user.ID, cred)
	assert.NoError(t, err)
	err = svc.RemoveWebAuthnCredential(ctx, user.ID, "cid")
	assert.NoError(t, err)
}

func TestUserService_GetAllActiveAndPhantomUserIDs(t *testing.T) {
	_, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	ctx := context.Background()
	user1, _ := svc.CreatePhantomUser(ctx, "a1@example.com")
	user2, _ := svc.CreatePhantomUser(ctx, "a2@example.com")
	// Activate user1
	svc.SetUserCredentials(ctx, user1.ID, models.AuthTypePasswordOnly, "pw")
	ids, err := svc.GetAllActiveUserIDs(ctx)
	assert.NoError(t, err)
	assert.Contains(t, ids, user1.ID)
	phantoms, err := svc.GetAllPhantomUserIDs(ctx)
	assert.NoError(t, err)
	assert.Contains(t, phantoms, user2.ID)
}

func TestUserService_DeleteUserAndListings(t *testing.T) {
	_, _, svc, cleanup := setupUserServiceTest(t)
	defer cleanup()
	ctx := context.Background()
	user, _ := svc.CreatePhantomUser(ctx, "del@example.com")
	err := svc.DeleteUserAndListings(ctx, user.ID)
	assert.NoError(t, err)
	fetched, err := svc.FindByID(ctx, user.ID)
	assert.Error(t, err)
	assert.Nil(t, fetched)
}

// Helper to setup user for email change tests
func setupUserWithEmailChange(t *testing.T, db *mongo.Database) (*models.User, *models.EmailChange) {
	t.Helper()
	ctx := context.Background()
	coll := db.Collection("users")
	user := &models.User{
		ID:    utils.NewSixID(),
		Email: "initial@example.com",
		EmailChange: &models.EmailChange{
			NewAddress:      "pending@example.com",
			ApprovedFromOld: false, // Start with flags false
			ConfirmedNew:    false,
		},
		Activated: true,
	}
	_, err := coll.InsertOne(ctx, user)
	require.NoError(t, err)
	return user, user.EmailChange
}
