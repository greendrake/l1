package services

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

var testMongoURIUserVal string

func init() {
	// Get current file path
	_, filename, _, _ := runtime.Caller(0)
	// Try to load .env from project root (3 levels up from this file)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	if err := godotenv.Load(filepath.Join(projectRoot, ".env")); err != nil {
		// Try current directory as fallback
		godotenv.Load()
	}

	testMongoURIUserVal = os.Getenv("MONGO_URI_TEST")
	if testMongoURIUserVal == "" {
		panic("MONGO_URI_TEST environment variable is required for tests")
	}
}

func setupTestDBUserVal(t *testing.T, dbName string) *mongo.Database {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(testMongoURIUserVal))
	require.NoError(t, err, "Failed to connect to MongoDB")
	db := client.Database(dbName)
	_ = db.Collection("user_validation_types").Drop(context.Background())
	_ = db.Collection("user_validations").Drop(context.Background())
	return db
}

func TestUserValidationService_CRUD(t *testing.T) {
	db := setupTestDBUserVal(t, "testdb_user_validation_service_crud")
	cfg := &config.Config{AppName: "TestApp"}
	svc := NewUserValidationService(db, cfg)
	ctx := context.Background()

	// Insert a validation type
	typeID := utils.NewSixID()
	vt := models.UserValidationType{ID: typeID, Key: "domain", Type: models.ValidationTypeDomainOwnership, Config: map[string]interface{}{}}
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
	vt2 := models.UserValidationType{ID: typeID2, Key: "profile", Type: models.ValidationTypeOnlineProfile, Config: map[string]interface{}{"url_template": "https://example.com/{profile_id}"}}
	_, err = db.Collection("user_validation_types").InsertOne(ctx, vt2)
	assert.NoError(t, err)

	val2, err := svc.CreateOnlineProfileValidation(ctx, userID, typeID2, "profile123")
	assert.NoError(t, err)
	assert.Equal(t, userID, val2.UserID)
	assert.Equal(t, "profile123", val2.Data["profile_id"])
	assert.Contains(t, val2.Data["profile_url"], "profile123")
}
