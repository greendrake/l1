package db

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/models"
)

const DefaultMaxRetries = 7

func InsertOne(ctx context.Context, collection *mongo.Collection, doc models.IBase) (models.IBase, error) {
	var err error
	// Loop for initial attempt (attempt = 0) + maxRetries
	doc.GenIDIfEmpty()
	for attempt := 0; attempt <= DefaultMaxRetries; attempt++ {
		_, err := collection.InsertOne(ctx, doc)
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

// IsMongoDuplicateKeyError checks if an error from MongoDB is a duplicate key error (code 11000).
func isMongoDuplicateKeyError(err error) bool {
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
