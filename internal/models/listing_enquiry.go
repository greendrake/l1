package models

import (
	"time"

	"greendrake/l1/internal/utils"
)

// ListingEnquiry represents an enquiry made about a listing.
type ListingEnquiry struct {
	ID        utils.SixID  `bson:"_id,omitempty" json:"id,omitempty"`
	ListingID utils.SixID  `bson:"listing_id" json:"listing_id"`
	UserID    utils.SixID  `bson:"user_id,omitempty" json:"user_id,omitempty"` // ID of user making enquiry (if logged in)
	UserEmail string       `bson:"user_email" json:"user_email"`               // Reply-to email provided
	Offer     *AskingPrice `bson:"offer,omitempty" json:"offer,omitempty"`     // Optional offer
	Message   string       `bson:"message" json:"message"`                     // Required if no offer
	CreatedAt time.Time    `bson:"created_at" json:"created_at"`
	Sent      bool         `bson:"sent" json:"sent"` // False initially, true after background task sends email
	Deleted   bool         `bson:"deleted" json:"-"` // Soft delete flag
}
