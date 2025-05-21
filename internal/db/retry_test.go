package db

import (
	"errors"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/utils"
)

// mockMongoDuplicateKeyError creates an error that IsMongoDuplicateKeyError will recognize.
func mockMongoDuplicateKeyError(key string) error {
	// IsMongoDuplicateKeyError checks for mongo.WriteException and then for code 11000.
	// We can simulate this by creating a WriteException with a WriteError that has code 11000.
	mongoErr := mongo.WriteError{
		Code:    11000, // Duplicate key error code
		Message: fmt.Sprintf("E11000 duplicate key error collection: test.collection index: _id_ dup key: { : \"%s\" }", key),
	}
	// The actual WriteException might have more fields, but this should be enough for IsMongoDuplicateKeyError.
	// It expects a mongo.WriteException which has a WriteErrors field (slice of WriteError).
	return mongo.WriteException{WriteErrors: []mongo.WriteError{mongoErr}}
}

func TestWithRetries_SuccessfulFirstAttempt(t *testing.T) {
	var opCalled int
	operation := func() error {
		opCalled++
		return nil // Simulate successful operation
	}

	err := WithRetries(operation, 3, IsMongoDuplicateKeyError)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if opCalled != 1 {
		t.Errorf("Expected operation to be called 1 time, got %d", opCalled)
	}
}

func TestWithRetries_FailureNonDuplicateKey(t *testing.T) {
	var opCalled int
	expectedErr := errors.New("some other error")
	operation := func() error {
		opCalled++
		return expectedErr
	}

	err := WithRetries(operation, 3, IsMongoDuplicateKeyError)
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
	if opCalled != 1 {
		t.Errorf("Expected operation to be called 1 time, got %d", opCalled)
	}
}

func TestWithRetries_ExhaustRetries(t *testing.T) {
	var opCalled int
	// This ID will be used by the mock operation to generate a duplicate key error
	collidingID := utils.SixID{0, 0, 0, 0, 0, 1}

	operation := func() error {
		opCalled++
		// Always return a duplicate key error for this test
		return mockMongoDuplicateKeyError(collidingID.String())
	}

	maxRetries := 3
	err := WithRetries(operation, maxRetries, IsMongoDuplicateKeyError)

	// Expecting a duplicate key error after all retries
	if err == nil {
		t.Fatal("Expected a duplicate key error, got nil")
	}
	if !IsMongoDuplicateKeyError(err) {
		t.Errorf("Expected a Mongo duplicate key error, got %T: %v", err, err)
	}

	expectedOpCalls := maxRetries + 1
	if opCalled != expectedOpCalls {
		t.Errorf("Expected operation to be called %d times, got %d", expectedOpCalls, opCalled)
	}
}

func TestWithRetries_CollisionResolves(t *testing.T) {
	originalHook := utils.NewSixIDHook
	defer func() { utils.NewSixIDHook = originalHook }() // Restore original hook

	id1 := utils.SixID{1, 2, 3, 4, 5, 1}
	id2 := utils.SixID{1, 2, 3, 4, 5, 2} // Different ID to resolve collision

	idsToReturn := []utils.SixID{id1, id1, id2} // NewSixID() will provide: id1 (dup), id1 (dup), id2 (ok)
	hookCallCount := 0
	utils.NewSixIDHook = func() (utils.SixID, bool) {
		if hookCallCount < len(idsToReturn) {
			id := idsToReturn[hookCallCount]
			hookCallCount++
			// fmt.Printf("Hook: returning ID %s (call #%d)\n", id.String(), hookCallCount)
			return id, true
		}
		return utils.SixID{}, false
	}

	insertedIDs := make(map[utils.SixID]bool)
	// Pre-populate to make the first attempt with id1 a collision
	insertedIDs[id1] = true

	var opCalled int

	operation := func() error {
		opCalled++
		newID := utils.NewSixID() // This will use our hook

		if insertedIDs[newID] {
			return mockMongoDuplicateKeyError(newID.String())
		}
		insertedIDs[newID] = true
		fmt.Printf("Test: Op attempt %d, trying to insert ID %s\n", opCalled, newID.String())
		return nil
	}

	maxRetries := 3
	err := WithRetries(operation, maxRetries, IsMongoDuplicateKeyError)

	if err != nil {
		t.Fatalf("Expected no error as collision should resolve, got: %v", err)
	}

	// Operation: 1st call (id1, success), 2nd call (id1, collision), 3rd call (id2, success)
	expectedOpCalls := 3
	if opCalled != expectedOpCalls {
		t.Errorf("Expected operation to be called %d times, got %d", expectedOpCalls, opCalled)
	}

	if !insertedIDs[id1] {
		t.Errorf("Expected ID %s to be inserted", id1.String())
	}
	if !insertedIDs[id2] {
		t.Errorf("Expected ID %s to be inserted after retry", id2.String())
	}
	if len(insertedIDs) != 2 {
		t.Errorf("Expected 2 unique IDs to be inserted, got %d", len(insertedIDs))
	}

	// Hook should be called for each ID generation attempt within the operation
	// Op1 (fails): NewSixID() -> id1. hookCallCount = 1.
	// Op2 (fails): NewSixID() -> id1. hookCallCount = 2.
	// Op3 (succeeds): NewSixID() -> id2. hookCallCount = 3.
	expectedHookCalls := 3
	if hookCallCount != expectedHookCalls {
		t.Errorf("Expected NewSixIDHook to be called %d times, got %d", expectedHookCalls, hookCallCount)
	}
}
