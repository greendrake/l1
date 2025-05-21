package db

import (
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

// Operation is a function that performs an action and returns an error if it fails.
type Operation func() error

// IsDuplicateKeyError is a function that checks if an error is a duplicate key error.
type IsDuplicateKeyError func(err error) bool

const DefaultMaxRetries = 3

// Try executes an operation with default retry settings for duplicate key errors.
// It uses DefaultMaxRetries and IsMongoDuplicateKeyError.
func Try(op Operation) error {
	return WithRetries(op, DefaultMaxRetries, IsMongoDuplicateKeyError)
}

// WithRetries executes an operation with a retry mechanism for duplicate key errors.
// It attempts the operation up to maxRetries times.
// A delay can be introduced between retries if needed, but is not implemented here for simplicity.
func WithRetries(op Operation, maxRetries int, isDuplicateKey IsDuplicateKeyError) error {
	var err error
	// Loop for initial attempt (attempt = 0) + maxRetries
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = op()
		if err == nil {
			return nil // Success
		}

		// If this was the last attempt (either initial if maxRetries = 0, or the last retry)
		// and it failed, break out of the loop to return the error.
		if attempt == maxRetries {
			break
		}

		if isDuplicateKey(err) {
			// Optional: log the retry attempt
			// log.Printf("Duplicate key error on attempt %d, retrying...", attempt+1)
			// Optional: add a small delay before retrying
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond) // Simple incremental backoff
			// Continue to the next attempt (handled by the loop)
		} else {
			return err // Not a duplicate key error, return immediately
		}
	}
	return err // All attempts failed or last attempt failed
}

// IsMongoDuplicateKeyError checks if an error from MongoDB is a duplicate key error (code 11000).
func IsMongoDuplicateKeyError(err error) bool {
	var e mongo.WriteException
	if errors.As(err, &e) {
		for _, we := range e.WriteErrors {
			if we.Code == 11000 {
				return true
			}
		}
	}
	// Also check for BulkWriteException, which can contain duplicate key errors
	var bwe mongo.BulkWriteException
	if errors.As(err, &bwe) {
		for _, writeError := range bwe.WriteErrors {
			if writeError.Code == 11000 {
				return true
			}
		}
	}
	return false
}
