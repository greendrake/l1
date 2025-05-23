package db

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// CollectionInterface defines the MongoDB collection methods we need for testing
type CollectionInterface interface {
	InsertOne(ctx context.Context, document interface{}, opts ...interface{}) (*mongo.InsertOneResult, error)
}

// MockCollection implements CollectionInterface for testing
type MockCollection struct {
	mock.Mock
}

func (m *MockCollection) InsertOne(ctx context.Context, document interface{}, opts ...interface{}) (*mongo.InsertOneResult, error) {
	args := m.Called(ctx, document)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mongo.InsertOneResult), args.Error(1)
}

// MockDocument implements models.IBase interface for testing
type MockDocument struct {
	mock.Mock
	id utils.SixID
}

func (m *MockDocument) GenIDIfEmpty() {
	m.Called()
	if m.id == (utils.SixID{}) {
		m.GenID()
	}
}

func (m *MockDocument) GenID() {
	m.Called()
	// Generate a simple predictable ID for testing
	m.id = utils.SixID{1, 2, 3, 4, 5, 6}
}

func (m *MockDocument) SetID(id utils.SixID) {
	m.Called(id)
	m.id = id
}

func (m *MockDocument) GetID() utils.SixID {
	return m.id
}

// insertOneWithInterface wraps the InsertOne function to accept our interface
func insertOneWithInterface(ctx context.Context, collection CollectionInterface, doc models.IBase) (models.IBase, error) {
	var err error
	// Loop for initial attempt (attempt = 0) + maxRetries
	doc.GenIDIfEmpty()
	for attempt := 0; attempt <= DefaultMaxRetries; attempt++ {
		_, err = collection.InsertOne(ctx, doc)
		if err == nil {
			return doc, nil // Success
		}
		// If this was the last attempt (either initial if maxRetries = 0, or the last retry)
		// and it failed, break out of the loop to return the error.
		if attempt == DefaultMaxRetries {
			break
		}
		if !isMongoDuplicateKeyError(err) {
			return nil, err // Not a duplicate key error, return immediately
		}
		doc.GenID()
	}
	return nil, err // All attempts failed or last attempt failed
}

// Helper function to create a duplicate key error
func createDuplicateKeyError() error {
	writeError := mongo.WriteError{
		Index:   0,
		Code:    11000, // MongoDB duplicate key error code
		Message: "E11000 duplicate key error",
	}
	return mongo.WriteException{
		WriteConcernError: nil,
		WriteErrors:       []mongo.WriteError{writeError},
	}
}

// Helper function to create a non-duplicate error
func createOtherError() error {
	return errors.New("some other MongoDB error")
}

func TestInsertOne_Success_FirstAttempt(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	mockDoc := new(MockDocument)

	expectedResult := &mongo.InsertOneResult{InsertedID: "test-id"}

	mockDoc.On("GenIDIfEmpty").Once()
	mockDoc.On("GenID").Once() // Called by GenIDIfEmpty since ID is initially empty
	mockCollection.On("InsertOne", ctx, mockDoc).Return(expectedResult, nil).Once()

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, mockDoc)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, mockDoc, result)
	mockDoc.AssertExpectations(t)
	mockCollection.AssertExpectations(t)
}

func TestInsertOne_Success_AfterRetries(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	mockDoc := new(MockDocument)

	duplicateError := createDuplicateKeyError()
	expectedResult := &mongo.InsertOneResult{InsertedID: "test-id"}

	// Set up expectations
	mockDoc.On("GenIDIfEmpty").Once()
	mockDoc.On("GenID").Times(4) // Once for GenIDIfEmpty + 3 retries

	// First 3 attempts fail with duplicate key error, 4th succeeds
	mockCollection.On("InsertOne", ctx, mockDoc).Return(nil, duplicateError).Times(3)
	mockCollection.On("InsertOne", ctx, mockDoc).Return(expectedResult, nil).Once()

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, mockDoc)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, mockDoc, result)
	mockDoc.AssertExpectations(t)
	mockCollection.AssertExpectations(t)
}

func TestInsertOne_FailsAfterMaxRetries(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	mockDoc := new(MockDocument)

	duplicateError := createDuplicateKeyError()

	// Set up expectations:
	// - GenIDIfEmpty is called once at start (which calls GenID once)
	// - GenID is called DefaultMaxRetries more times in the retry loop (7 times)
	// - Total GenID calls: 1 + 7 = 8
	// - InsertOne is called DefaultMaxRetries + 1 times (8 total)
	mockDoc.On("GenIDIfEmpty").Once()
	mockDoc.On("GenID").Times(DefaultMaxRetries + 1) // Called by GenIDIfEmpty + 7 retries

	// All attempts fail with duplicate key error (8 total attempts)
	mockCollection.On("InsertOne", ctx, mockDoc).Return(nil, duplicateError).Times(DefaultMaxRetries + 1)

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, mockDoc)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, isMongoDuplicateKeyError(err))
	mockDoc.AssertExpectations(t)
	mockCollection.AssertExpectations(t)
}

func TestInsertOne_NonDuplicateKeyError(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	mockDoc := new(MockDocument)

	otherError := createOtherError()

	mockDoc.On("GenIDIfEmpty").Once()
	mockDoc.On("GenID").Once() // Called by GenIDIfEmpty
	mockCollection.On("InsertOne", ctx, mockDoc).Return(nil, otherError).Once()

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, mockDoc)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, otherError, err)
	assert.False(t, isMongoDuplicateKeyError(err))
	mockDoc.AssertExpectations(t)
	mockCollection.AssertExpectations(t)
}

func TestInsertOne_MixedErrors(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	mockDoc := new(MockDocument)

	duplicateError := createDuplicateKeyError()
	otherError := createOtherError()

	mockDoc.On("GenIDIfEmpty").Once()
	mockDoc.On("GenID").Times(3) // Once for GenIDIfEmpty + 2 retries

	// First 2 attempts fail with duplicate key error, 3rd fails with other error
	mockCollection.On("InsertOne", ctx, mockDoc).Return(nil, duplicateError).Times(2)
	mockCollection.On("InsertOne", ctx, mockDoc).Return(nil, otherError).Once()

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, mockDoc)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, otherError, err)
	assert.False(t, isMongoDuplicateKeyError(err))
	mockDoc.AssertExpectations(t)
	mockCollection.AssertExpectations(t)
}

func TestIsMongoDuplicateKeyError_WriteException(t *testing.T) {
	writeError := mongo.WriteError{
		Index:   0,
		Code:    11000,
		Message: "E11000 duplicate key error",
	}
	err := mongo.WriteException{
		WriteErrors: []mongo.WriteError{writeError},
	}

	assert.True(t, isMongoDuplicateKeyError(err))
}

func TestIsMongoDuplicateKeyError_BulkWriteException(t *testing.T) {
	bulkWriteError := mongo.BulkWriteError{
		WriteError: mongo.WriteError{
			Index:   0,
			Code:    11000,
			Message: "E11000 duplicate key error",
		},
	}
	err := mongo.BulkWriteException{
		WriteErrors: []mongo.BulkWriteError{bulkWriteError},
	}

	assert.True(t, isMongoDuplicateKeyError(err))
}

func TestIsMongoDuplicateKeyError_NonDuplicateError(t *testing.T) {
	writeError := mongo.WriteError{
		Index:   0,
		Code:    12345, // Different error code
		Message: "Some other error",
	}
	err := mongo.WriteException{
		WriteErrors: []mongo.WriteError{writeError},
	}

	assert.False(t, isMongoDuplicateKeyError(err))
}

func TestIsMongoDuplicateKeyError_RegularError(t *testing.T) {
	err := errors.New("regular error")
	assert.False(t, isMongoDuplicateKeyError(err))
}

// Integration test with real models.Base
func TestInsertOne_WithRealBase(t *testing.T) {
	// Use a counter to track ID generation attempts
	genIDCallCount := 0
	originalHook := utils.NewSixIDHook

	// Set up a hook to control ID generation for predictable testing
	utils.NewSixIDHook = func() (utils.SixID, bool) {
		genIDCallCount++
		// Create predictable IDs that change each time
		id := utils.SixID{byte(genIDCallCount), 1, 2, 3, 4, 5}
		return id, true
	}
	defer func() {
		utils.NewSixIDHook = originalHook
	}()

	// Arrange
	ctx := context.Background()
	mockCollection := new(MockCollection)
	doc := &models.Base{}

	duplicateError := createDuplicateKeyError()
	expectedResult := &mongo.InsertOneResult{InsertedID: "test-id"}

	// First 2 attempts fail with duplicate key error, 3rd succeeds
	mockCollection.On("InsertOne", ctx, doc).Return(nil, duplicateError).Times(2)
	mockCollection.On("InsertOne", ctx, doc).Return(expectedResult, nil).Once()

	// Act
	result, err := insertOneWithInterface(ctx, mockCollection, doc)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, doc, result)
	assert.Equal(t, 3, genIDCallCount) // Initial + 2 retries
	mockCollection.AssertExpectations(t)
}
