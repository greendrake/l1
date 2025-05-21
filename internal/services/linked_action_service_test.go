package services

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

var testMongoURILinkedAction = ""

func init() {
	testMongoURILinkedAction = os.Getenv("MONGO_URI_TEST")
	if testMongoURILinkedAction == "" {
		testMongoURILinkedAction = "mongodb://localhost:27017"
	}
}

func setupTestDBLinkedAction(t *testing.T, dbName string) *mongo.Database {
	// Create a clean database for testing
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(testMongoURILinkedAction))
	if err != nil {
		t.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Drop the database if it exists
	err = client.Database(dbName).Drop(context.Background())
	if err != nil {
		// Ignore error if the database doesn't exist
		t.Logf("Database drop error (may be normal): %v", err)
	}

	// Create a fresh database
	db := client.Database(dbName)
	return db
}

// mockUserServiceForLASTest is a local mock for IUserService
type mockUserServiceForLASTest struct {
	mock.Mock // Embed testify's mock for easier method mocking if needed later
}

func (m *mockUserServiceForLASTest) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *mockUserServiceForLASTest) CreatePhantomUser(ctx context.Context, email string) (*models.User, error) {
	return nil, nil
} // No-op
func (m *mockUserServiceForLASTest) SetUserCredentials(ctx context.Context, userID utils.SixID, authType models.AuthType, password string) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) FindByID(ctx context.Context, userID utils.SixID) (*models.User, error) {
	// For CreateEmailChangeActions, this might be called. Return a dummy user.
	// If specific tests need specific user data, they can set expectations on this mock.
	return &models.User{ID: userID, Email: "test@example.com"}, nil
}
func (m *mockUserServiceForLASTest) GetAllActiveUserIDs(ctx context.Context) ([]utils.SixID, error) {
	return nil, nil
} // No-op
func (m *mockUserServiceForLASTest) GetAllPhantomUserIDs(ctx context.Context) ([]utils.SixID, error) {
	return nil, nil
} // No-op
func (m *mockUserServiceForLASTest) DeleteUserAndListings(ctx context.Context, userID utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) SuspendUser(ctx context.Context, userIDToSuspend, adminUserID utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) UnsuspendUser(ctx context.Context, userIDToUnsuspend utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) RequestEmailChange(ctx context.Context, userID utils.SixID, newEmail string) (*models.LinkedAction, *models.LinkedAction, error) {
	return nil, nil, nil
} // No-op
func (m *mockUserServiceForLASTest) ApproveEmailChangeOld(ctx context.Context, userID utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) ConfirmEmailChangeNew(ctx context.Context, userID utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) FinalizeEmailChange(ctx context.Context, userID utils.SixID) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) SetOTPSecret(ctx context.Context, userID utils.SixID, otpSecret string) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) AddWebAuthnCredential(ctx context.Context, userID utils.SixID, cred models.WebAuthnCredential) error {
	return nil
} // No-op
func (m *mockUserServiceForLASTest) RemoveWebAuthnCredential(ctx context.Context, userID utils.SixID, credentialID string) error {
	return nil
}                                                                                    // No-op
func (m *mockUserServiceForLASTest) SetLinkedActionService(las ILinkedActionService) {} // No-op, satisfies interface

func TestLinkedActionService_CRUD(t *testing.T) {
	// Use a unique database name for this test to isolate it
	dbName := fmt.Sprintf("testdb_linked_action_service_crud_%d", time.Now().UnixNano())

	// First drop the collection to ensure no leftover test data
	db := setupTestDBLinkedAction(t, dbName)
	collection := db.Collection("linked_actions")
	err := collection.Drop(context.Background())
	require.NoError(t, err)

	// Setup config and service
	cfg := &config.Config{LoginToSetupTTL: 1 * time.Hour, ResetAccessLinkTTL: 30 * time.Minute, EmailChangeTTL: 1 * time.Hour}
	mockUserSvc := &mockUserServiceForLASTest{}
	svc := NewLinkedActionService(db, cfg, mockUserSvc)
	ctx := context.Background()
	userID := utils.NewSixID()

	// First test - create login action
	t.Run("CreateLoginAction", func(t *testing.T) {
		action, err := svc.CreateLoginToSetupAction(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, userID, action.UserID)
		assert.Equal(t, models.ActionLoginToSetupAccount, action.Type)
		require.NotEmpty(t, action.ID.String())

		// Test successful validation
		foundAction, err := svc.FindAndValidateAction(ctx, action.ID.String(), nil)
		require.NoError(t, err)
		require.NotNil(t, foundAction)
		// IDs should match when comparing Crockford Base32 strings
		assert.Equal(t, action.ID.String(), foundAction.ID.String())

		// Test validation failure (wrong user ID)
		wrongUserID := utils.NewSixID()
		// Should still work with Crockford Base32 format
		_, err = svc.FindAndValidateAction(ctx, action.ID.String(), &wrongUserID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "action link is invalid, expired, or already used")

		// Mark executed
		err = svc.MarkActionExecuted(ctx, action.ID)
		assert.NoError(t, err)

		// Should not find again (already executed)
		// Using Crockford Base32 string representation
		_, err = svc.FindAndValidateAction(ctx, action.ID.String(), nil)
		assert.Error(t, err)
	})

	// Second test - create reset action
	t.Run("CreateResetAction", func(t *testing.T) {
		action2, err := svc.CreateResetAccessAction(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, userID, action2.UserID)
		assert.Equal(t, models.ActionLoginToSetupAccount, action2.Type)
		require.NotEmpty(t, action2.ID.String())
	})
}
