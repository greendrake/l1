package utils

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var testMongoURI string

func init() {
	loadTestEnv()
}

// loadTestEnv loads the .env file and sets up test environment variables
func loadTestEnv() {
	// Get current file path
	_, filename, _, _ := runtime.Caller(0)
	// Try to load .env from project root (2 levels up from this file)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	if err := godotenv.Load(filepath.Join(projectRoot, ".env")); err != nil {
		// Try current directory as fallback
		godotenv.Load()
	}

	testMongoURI = os.Getenv("MONGO_URI")
	if testMongoURI == "" {
		panic("MONGO_URI environment variable is required for tests")
	}
}

// SetupTestDB creates a test MongoDB database connection and returns the database instance
// It also drops any existing collections to ensure a clean state
func SetupTestDB(t *testing.T, dbName string, collections ...string) *mongo.Database {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(testMongoURI))
	require.NoError(t, err, "Failed to connect to MongoDB")
	db := client.Database(dbName)

	// Drop specified collections for clean state
	for _, collection := range collections {
		_ = db.Collection(collection).Drop(context.Background())
	}

	return db
}

// GetTestMongoURI returns the test MongoDB URI for direct use if needed
func GetTestMongoURI() string {
	if testMongoURI == "" {
		loadTestEnv()
	}
	return testMongoURI
}
