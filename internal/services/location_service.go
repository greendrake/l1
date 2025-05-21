package services

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/models"
)

// ILocationService defines the interface for location operations.
type ILocationService interface {
	SearchLocations(ctx context.Context, query string, countryCode *string, limit int) ([]models.Location, error)
}

const locationsCollection = "locations"

// locationService implements ILocationService.
type locationService struct {
	db *mongo.Database
}

// NewLocationService creates a new LocationService.
func NewLocationService(db *mongo.Database) ILocationService {
	return &locationService{db: db}
}

// SearchLocations searches the locations collection by name/alt_names using text search.
// Optionally filters by countryCode. Returns results sorted population.
func (s *locationService) SearchLocations(ctx context.Context, query string, countryCode *string, limit int) ([]models.Location, error) {
	collection := s.db.Collection(locationsCollection)

	filter := bson.M{
		"$text": bson.M{"$search": query},
	}
	if countryCode != nil {
		filter["country_code"] = *countryCode
	}

	sort := bson.D{
		{Key: "population", Value: -1},
	}

	projection := bson.D{
		{Key: "_id", Value: 1},
		{Key: "name", Value: 1},
		{Key: "country_code", Value: 1},
		{Key: "context", Value: 1},
		{Key: "population", Value: 1},
		{Key: "location", Value: 1},
	}

	opts := options.Find().
		SetSort(sort).
		SetProjection(projection).
		SetLimit(int64(limit))

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to execute location search query: %w", err)
	}
	defer cursor.Close(ctx)

	var results []models.Location
	if err = cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode location search results: %w", err)
	}

	return results, nil
}
