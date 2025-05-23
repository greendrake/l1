package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

func setupTestDBUserVal(t *testing.T, dbName string) *mongo.Database {
	return utils.SetupTestDB(t, dbName, "user_validation_types", "user_validations")
}

func TestUserValidationService_CRUD(t *testing.T) {
	db := setupTestDBUserVal(t, "testdb_user_validation_service_crud")
	cfg := &config.Config{AppName: "TestApp"}
	svc := NewUserValidationService(db, cfg)
	ctx := context.Background()

	// Insert a validation type
	typeID := utils.NewSixID()
	vt := models.UserValidationType{Base: models.Base{ID: typeID}, Key: "domain", Type: models.ValidationTypeDomainOwnership, Config: map[string]interface{}{}}
	_, err := db.Collection("user_validation_types").InsertOne(ctx, vt)
	assert.NoError(t, err)

	types, err := svc.GetValidationTypes(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, types)

	vtFetched, err := svc.GetValidationTypeByID(ctx, typeID)
	assert.NoError(t, err)
	assert.Equal(t, typeID, vtFetched.ID)

	// Create domain validation
	userID := utils.NewSixID()
	val, err := svc.CreateDomainValidation(ctx, userID, typeID, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, userID, val.UserID)
	assert.Equal(t, "example.com", val.Data["domain_name"])

	// Get validation by ID
	valFetched, err := svc.GetValidationByID(ctx, val.ID)
	assert.NoError(t, err)
	assert.Equal(t, val.ID, valFetched.ID)

	// Confirm validation
	err = svc.ConfirmValidation(ctx, val.ID)
	assert.NoError(t, err)

	// Create online profile validation type
	typeID2 := utils.NewSixID()
	vt2 := models.UserValidationType{Base: models.Base{ID: typeID2}, Key: "profile", Type: models.ValidationTypeOnlineProfile, Config: map[string]interface{}{"url_template": "https://example.com/{profile_id}"}}
	_, err = db.Collection("user_validation_types").InsertOne(ctx, vt2)
	assert.NoError(t, err)

	val2, err := svc.CreateOnlineProfileValidation(ctx, userID, typeID2, "profile123")
	assert.NoError(t, err)
	assert.Equal(t, userID, val2.UserID)
	assert.Equal(t, "profile123", val2.Data["profile_id"])
	assert.Contains(t, val2.Data["profile_url"], "profile123")
}
