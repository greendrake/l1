package services

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

var testMongoURIBilling = ""

func init() {
	testMongoURIBilling = os.Getenv("MONGO_URI_TEST")
	if testMongoURIBilling == "" {
		testMongoURIBilling = "mongodb://localhost:27017"
	}
}

func setupTestDBBilling(t *testing.T, dbName string) *mongo.Database {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(testMongoURIBilling))
	if err != nil {
		t.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	db := client.Database(dbName)
	_ = db.Collection("invoices").Drop(context.Background())
	_ = db.Collection("users").Drop(context.Background())
	return db
}

type mockConfigService struct{}

func (m *mockConfigService) Get(ctx context.Context, key string) (interface{}, error) {
	return nil, nil
}
func (m *mockConfigService) GetInt(ctx context.Context, key string, defaultValue int) int {
	return defaultValue
}
func (m *mockConfigService) GetString(ctx context.Context, key string, defaultValue string) string {
	return defaultValue
}
func (m *mockConfigService) GetBool(ctx context.Context, key string, defaultValue bool) bool {
	return defaultValue
}
func (m *mockConfigService) GetFloat64(ctx context.Context, key string, defaultValue float64) float64 {
	return defaultValue
}
func (m *mockConfigService) GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration {
	return defaultValue
}
func (m *mockConfigService) GetAllPublic(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}
func (m *mockConfigService) Load(ctx context.Context) error               { return nil }
func (m *mockConfigService) SubscribeToChanges(ctx context.Context) error { return nil }
func (m *mockConfigService) SetConfigValue(ctx context.Context, key string, value interface{}, isPublic bool) error {
	return nil
}
func (m *mockConfigService) GetAPIEndpointConfig(ctx context.Context, apiType models.APIType, endpoint string, isAuthenticated bool) (*models.APIEndpointConfig, error) {
	return nil, nil
}

func TestBillingService_GenerateInvoice(t *testing.T) {
	db := setupTestDBBilling(t, "testdb_billing_service_invoice")
	cfg := &config.Config{InvoicePaymentWaitTimeDays: 7}
	mockCfg := &mockConfigService{}
	listingSvc := &mockListingService{}
	userSvc := &mockUserService{}
	svc := NewBillingService(db, cfg, mockCfg, listingSvc, userSvc)
	ctx := context.Background()
	userID := utils.NewSixID()
	items := []models.InvoiceLineItem{{ListingID: utils.NewSixID(), ListingTitle: "Test", StartDate: time.Now(), BilledUntil: time.Now().Add(24 * time.Hour), Amount: 10.0}}
	invoice, err := svc.GenerateInvoice(ctx, userID, items, 10.0, "USD")
	assert.NoError(t, err)
	assert.Equal(t, userID, invoice.UserID)
	assert.Equal(t, 10.0, invoice.Subtotal)
	assert.Equal(t, "USD", invoice.CurrencyCode)
}

// Add more tests for CalculateChargesForUser, FindOverdueInvoices, MarkInvoiceOverdueNotified, etc. as needed.

type mockListingService struct{}

func (m *mockListingService) CreateListing(ctx context.Context, userID utils.SixID, title, body string, tags []string, locationID int, countryCode, shipping string, askingPrice *models.AskingPrice) (*models.Listing, error) {
	return &models.Listing{ID: utils.NewSixID(), UserID: userID, Title: title, Body: body, Tags: tags, LocationID: locationID, CountryCode: countryCode, Shipping: shipping, AskingPrice: askingPrice}, nil
}
func (m *mockListingService) FindListingByID(ctx context.Context, listingID utils.SixID) (*models.Listing, error) {
	return &models.Listing{ID: listingID}, nil
}
func (m *mockListingService) UpdateListing(ctx context.Context, listingID, userID utils.SixID, updates map[string]interface{}) (*models.Listing, error) {
	return &models.Listing{ID: listingID, UserID: userID}, nil
}
func (m *mockListingService) PublishListing(ctx context.Context, listingID, userID utils.SixID) error {
	return nil
}
func (m *mockListingService) HideListing(ctx context.Context, listingID, userID utils.SixID) error {
	return nil
}
func (m *mockListingService) UnhideListing(ctx context.Context, listingID, userID utils.SixID) error {
	return nil
}
func (m *mockListingService) DeleteListing(ctx context.Context, listingID, userID utils.SixID) error {
	return nil
}
func (m *mockListingService) SearchListings(ctx context.Context, query *string, countryCode *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]models.Listing, string, error) {
	return nil, "", nil
}
func (m *mockListingService) AddImageToListing(ctx context.Context, listingID utils.SixID, imageKey string) error {
	return nil
}
func (m *mockListingService) FindLatestListingByUserID(ctx context.Context, userID utils.SixID) (*models.Listing, error) {
	return &models.Listing{ID: utils.NewSixID(), UserID: userID}, nil
}
func (m *mockListingService) SuspendListing(ctx context.Context, listingID, adminUserID utils.SixID, reason string) error {
	return nil
}
func (m *mockListingService) UnsuspendListing(ctx context.Context, listingID, adminUserID utils.SixID) error {
	return nil
}
func (m *mockListingService) GetListingSuspension(ctx context.Context, listingID utils.SixID) (*models.ListingSuspension, error) {
	return &models.ListingSuspension{ListingID: listingID}, nil
}
func (m *mockListingService) ListSuspendedListings(ctx context.Context, limit int) ([]models.ListingSuspension, error) {
	return nil, nil
}
func (m *mockListingService) FindListingsByUserID(ctx context.Context, userID utils.SixID) ([]models.Listing, error) {
	return nil, nil
}
func (m *mockListingService) SearchListingsByUser(ctx context.Context, userID utils.SixID, query *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]*models.Listing, *string, error) {
	return nil, nil, nil
}

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	return &models.User{Email: email}, nil
}
func (m *mockUserService) CreatePhantomUser(ctx context.Context, email string) (*models.User, error) {
	return &models.User{Email: email, Phantom: true}, nil
}
func (m *mockUserService) SetUserCredentials(ctx context.Context, userID utils.SixID, authType models.AuthType, password string) error {
	return nil
}
func (m *mockUserService) FindByID(ctx context.Context, userID utils.SixID) (*models.User, error) {
	return &models.User{ID: userID}, nil
}
func (m *mockUserService) GetAllActiveUserIDs(ctx context.Context) ([]utils.SixID, error) {
	return nil, nil
}
func (m *mockUserService) GetAllPhantomUserIDs(ctx context.Context) ([]utils.SixID, error) {
	return nil, nil
}
func (m *mockUserService) DeleteUserAndListings(ctx context.Context, userID utils.SixID) error {
	return nil
}
func (m *mockUserService) SuspendUser(ctx context.Context, userIDToSuspend, adminUserID utils.SixID) error {
	return nil
}
func (m *mockUserService) UnsuspendUser(ctx context.Context, userIDToUnsuspend utils.SixID) error {
	return nil
}
func (m *mockUserService) RequestEmailChange(ctx context.Context, userID utils.SixID, newEmail string) (*models.LinkedAction, *models.LinkedAction, error) {
	args := m.Called(ctx, userID, newEmail)
	var oldAction, newAction *models.LinkedAction
	if args.Get(0) != nil {
		oldAction = args.Get(0).(*models.LinkedAction)
	}
	if args.Get(1) != nil {
		newAction = args.Get(1).(*models.LinkedAction)
	}
	return oldAction, newAction, args.Error(2)
}
func (m *mockUserService) ApproveEmailChangeOld(ctx context.Context, userID utils.SixID) error {
	return nil
}
func (m *mockUserService) ConfirmEmailChangeNew(ctx context.Context, userID utils.SixID) error {
	return nil
}
func (m *mockUserService) FinalizeEmailChange(ctx context.Context, userID utils.SixID) error {
	return nil
}
func (m *mockUserService) SetOTPSecret(ctx context.Context, userID utils.SixID, otpSecret string) error {
	return nil
}
func (m *mockUserService) AddWebAuthnCredential(ctx context.Context, userID utils.SixID, cred models.WebAuthnCredential) error {
	return nil
}
func (m *mockUserService) RemoveWebAuthnCredential(ctx context.Context, userID utils.SixID, credentialID string) error {
	return nil
}

func (m *mockUserService) SetLinkedActionService(las ILinkedActionService) {
	// For this local mock, we might not need to do anything with m.Called(las)
	// unless we specifically want to assert that this setter was called.
	// For now, a no-op implementation is fine to satisfy the interface.
}

func TestBillingService_CalculateChargesForUser(t *testing.T) {
	// Implementation of TestBillingService_CalculateChargesForUser
}
