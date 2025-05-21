package models

import (
	"strings"
)

// GeoJSON represents a GeoJSON Point for MongoDB.
type GeoJSON struct {
	Type        string    `bson:"type" json:"type"`               // Should be "Point"
	Coordinates []float64 `bson:"coordinates" json:"coordinates"` // [longitude, latitude]
}

// Location represents a toponym document from the pre-populated collection.
type Location struct {
	ID          int      `bson:"_id,omitempty" json:"id,omitempty"`
	ParentID    int      `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
	Context     []string `bson:"context,omitempty" json:"context,omitempty"` // Array of ancestor names
	Location    *GeoJSON `bson:"location,omitempty" json:"location,omitempty"`
	Name        string   `bson:"name" json:"name"`
	CountryCode string   `bson:"country_code" json:"country_code"`
	AltNames    []string `bson:"alt_names,omitempty" json:"alt_names,omitempty"`
	Population  int      `bson:"population,omitempty" json:"population,omitempty"`
}

// LocationAPIResponse defines the structure for location data returned by APIs.
type LocationAPIResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Context     string    `json:"context,omitempty"`
	CountryCode string    `json:"country_code"`
	Coordinates []float64 `json:"coordinates,omitempty"` // [longitude, latitude]
}

// FormatContext takes a slice of context strings (e.g., ancestors of a location)
// and returns a single string with elements reversed and joined by ", ".
func FormatContext(contextElements []string) string {
	if len(contextElements) == 0 {
		return ""
	}
	// Reverse context slice
	reversedContext := make([]string, len(contextElements))
	for i, j := 0, len(contextElements)-1; j >= 0; i, j = i+1, j-1 {
		reversedContext[i] = contextElements[j]
	}
	return strings.Join(reversedContext, ", ")
}
