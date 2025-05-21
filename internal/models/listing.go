package models

import (
	"time"

	"greendrake/l1/internal/utils"
)

// AskingPrice defines the structure for monetary values.
type AskingPrice struct {
	Value        float64 `bson:"value" json:"value"`
	CurrencyCode string  `bson:"currency_code" json:"currency_code"`
}

// Listing represents a classified listing.
type Listing struct {
	ID           utils.SixID  `bson:"_id,omitempty" json:"id,omitempty"`
	UserID       utils.SixID  `bson:"user_id" json:"user_id"`
	Title        string       `bson:"title" json:"title"`
	Body         string       `bson:"body" json:"body"`
	Tags         []string     `bson:"tags" json:"tags"`
	Images       []string     `bson:"images" json:"images"` // S3 keys
	LocationID   int          `bson:"location" json:"location"`
	CountryCode  string       `bson:"country_code" json:"country_code"` // Denormalized from Location
	Shipping     string       `bson:"shipping" json:"shipping"`         // e.g., "pickup_only", "shipping_country_only", "shipping_worldwide"
	AskingPrice  *AskingPrice `bson:"asking_price,omitempty" json:"asking_price,omitempty"`
	IsDraft      bool         `bson:"is_draft" json:"is_draft"`
	UpdatedAt    time.Time    `bson:"updated_at" json:"updated_at"`
	CreatedAt    time.Time    `bson:"created_at" json:"created_at"`                         // Assumed needed
	PublishedAt  *time.Time   `bson:"published_at,omitempty" json:"published_at,omitempty"` // When IsDraft becomes false
	Phantom      bool         `bson:"phantom" json:"phantom"`
	Hidden       bool         `bson:"hidden" json:"hidden"`
	SuspensionID *utils.SixID `bson:"suspension,omitempty" json:"suspension,omitempty"` // Refers to ListingSuspensions doc
	Deleted      bool         `bson:"deleted" json:"-"`                                 // Soft delete flag
}

// ListingSuspension represents a suspension record for a listing.
type ListingSuspension struct {
	ID         utils.SixID `bson:"_id,omitempty" json:"id,omitempty"`
	ListingID  utils.SixID `bson:"listing_id" json:"listing_id"`
	UserID     utils.SixID `bson:"user_id" json:"user_id"` // Who reported/requested
	Reason     string      `bson:"reason" json:"reason"`
	ExecutedAt *time.Time  `bson:"executed,omitempty" json:"executed,omitempty"`
	Suspended  bool        `bson:"suspended" json:"suspended"`
	Deleted    bool        `bson:"deleted" json:"-"`
}
