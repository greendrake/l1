package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

func setupTestDBListing(t *testing.T, dbName string) *mongo.Database {
	return utils.SetupTestDB(t, dbName, "listings", "users", "listing_suspensions")
}

func createTestUser(db *mongo.Database, userID utils.SixID) error {
	user := models.User{
		Base:      models.Base{ID: userID},
		Email:     "test@example.com",
		Phantom:   false,
		Activated: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_, err := db.Collection("users").InsertOne(context.Background(), user)
	return err
}

func TestListingService_CRUD(t *testing.T) {
	db := setupTestDBListing(t, "testdb_listing_service_crud")
	cfg := &config.Config{}
	svc := NewListingService(db, cfg)
	ctx := context.Background()

	// Create a test user first
	userID := utils.NewSixID()
	err := createTestUser(db, userID)
	assert.NoError(t, err)

	// Create a listing
	locationID := 1
	title := "Test Listing"
	body := "Test Body"
	tags := []string{"tag1", "tag2"}
	countryCode := "US"
	shipping := "pickup_only"
	price := &models.AskingPrice{Value: 10.0, CurrencyCode: "USD"}

	listing, err := svc.CreateListing(ctx, userID, title, body, tags, locationID, countryCode, shipping, price)
	assert.NoError(t, err)
	assert.NotNil(t, listing)
	assert.Equal(t, title, listing.Title)

	// Find the created listing
	found, err := svc.FindListingByID(ctx, listing.ID)
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, listing.ID, found.ID)

	// Try to find non-existent listing
	nonExistentID := utils.NewSixID()
	notFound, err := svc.FindListingByID(ctx, nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, notFound)

	// Update the listing
	updates := map[string]interface{}{"title": "Updated Title", "body": "Updated Body"}
	updated, err := svc.UpdateListing(ctx, listing.ID, userID, updates)
	assert.NoError(t, err)
	assert.NotNil(t, updated)
	assert.Equal(t, "Updated Title", updated.Title)

	// Test listing state changes
	err = svc.PublishListing(ctx, listing.ID, userID)
	assert.NoError(t, err)

	err = svc.HideListing(ctx, listing.ID, userID)
	assert.NoError(t, err)

	err = svc.UnhideListing(ctx, listing.ID, userID)
	assert.NoError(t, err)

	// Delete the listing
	err = svc.DeleteListing(ctx, listing.ID, userID)
	assert.NoError(t, err)

	// Verify listing is deleted
	deleted, err := svc.FindListingByID(ctx, listing.ID)
	assert.Error(t, err)
	assert.Nil(t, deleted)

	// Try to update deleted listing
	_, err = svc.UpdateListing(ctx, listing.ID, userID, updates)
	assert.Error(t, err)
}

func TestListingService_FindLatestListingByUserID(t *testing.T) {
	db := setupTestDBListing(t, "testdb_listing_service_latest")
	cfg := &config.Config{}
	svc := NewListingService(db, cfg)
	ctx := context.Background()

	// Create a test user first
	userID := utils.NewSixID()
	err := createTestUser(db, userID)
	assert.NoError(t, err)

	locationID := 1
	_, _ = svc.CreateListing(ctx, userID, "Old", "Body", nil, locationID, "US", "pickup_only", nil)
	time.Sleep(1 * time.Second)
	latest, _ := svc.CreateListing(ctx, userID, "New", "Body", nil, locationID, "US", "pickup_only", nil)
	found, err := svc.FindLatestListingByUserID(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, latest.ID, found.ID)
}

func TestListingService_SuspendUnsuspend(t *testing.T) {
	db := setupTestDBListing(t, "testdb_listing_service_suspend")
	cfg := &config.Config{}
	svc := NewListingService(db, cfg)
	ctx := context.Background()

	// Create test users
	userID := utils.NewSixID()
	err := createTestUser(db, userID)
	assert.NoError(t, err)

	adminID := utils.NewSixID()
	err = createTestUser(db, adminID)
	assert.NoError(t, err)

	locationID := 1
	listing, _ := svc.CreateListing(ctx, userID, "Suspend", "Body", nil, locationID, "US", "pickup_only", nil)
	err = svc.SuspendListing(ctx, listing.ID, adminID, "violation")
	assert.NoError(t, err)
	susp, err := svc.GetListingSuspension(ctx, listing.ID)
	assert.NoError(t, err)
	assert.Equal(t, listing.ID, susp.ListingID)
	err = svc.UnsuspendListing(ctx, listing.ID, adminID)
	assert.NoError(t, err)
}

func TestListingService_AddImageToListing(t *testing.T) {
	db := setupTestDBListing(t, "testdb_listing_service_image")
	cfg := &config.Config{}
	svc := NewListingService(db, cfg)
	ctx := context.Background()

	// Create a test user first
	userID := utils.NewSixID()
	err := createTestUser(db, userID)
	assert.NoError(t, err)

	locationID := 1
	listing, _ := svc.CreateListing(ctx, userID, "Image", "Body", nil, locationID, "US", "pickup_only", nil)
	imageKey := "img1.jpg"
	err = svc.AddImageToListing(ctx, listing.ID, imageKey)
	assert.NoError(t, err)
	found, _ := svc.FindListingByID(ctx, listing.ID)
	assert.Contains(t, found.Images, imageKey)
}

func TestListingService_SearchListingsByUser(t *testing.T) {
	db := setupTestDBListing(t, "testdb_listing_service_searchuser")
	cfg := &config.Config{}
	svc := NewListingService(db, cfg)
	ctx := context.Background()

	// Create a test user first
	userID := utils.NewSixID()
	err := createTestUser(db, userID)
	assert.NoError(t, err)

	locationID := 1
	_, _ = svc.CreateListing(ctx, userID, "A", "Body", []string{"tag1"}, locationID, "US", "pickup_only", nil)
	_, _ = svc.CreateListing(ctx, userID, "B", "Body", []string{"tag2"}, locationID, "US", "pickup_only", nil)
	listings, _, err := svc.SearchListingsByUser(ctx, userID, nil, nil, nil, nil, 10, nil, "date_desc")
	assert.NoError(t, err)
	assert.True(t, len(listings) >= 2)
}
