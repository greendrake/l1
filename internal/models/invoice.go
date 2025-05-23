package models

import (
	"time"

	"greendrake/l1/internal/utils"
)

// InvoiceLineItem represents a single line item within an invoice.
type InvoiceLineItem struct {
	ListingID    utils.SixID `bson:"listing_id" json:"listing_id"`
	ListingTitle string      `bson:"listing_title" json:"listing_title"` // Denormalized for display
	StartDate    time.Time   `bson:"start" json:"start"`                 // Period start date
	BilledUntil  time.Time   `bson:"billed_until" json:"billed_until"`   // Period end date
	Amount       float64     `bson:"amount" json:"amount"`
}

// Invoice represents a bill issued to a user.
type Invoice struct {
	Base            `bson:",inline"`
	UserID          utils.SixID       `bson:"user_id" json:"user_id"`
	InvoiceNumber   string            `bson:"invoice_number" json:"invoice_number"` // Generate a unique readable number
	Items           []InvoiceLineItem `bson:"items" json:"items"`
	CurrencyCode    string            `bson:"currency_code" json:"currency_code"`
	Subtotal        float64           `bson:"subtotal" json:"subtotal"`
	Tax             float64           `bson:"tax" json:"tax"` // TODO: Tax calculation logic?
	Total           float64           `bson:"total" json:"total"`
	IssuedAt        time.Time         `bson:"issued_at" json:"issued_at"`
	DueAt           time.Time         `bson:"due" json:"due"`
	Sent            bool              `bson:"sent" json:"sent"`                           // False initially, true after email task
	PaidAt          *time.Time        `bson:"paid_at,omitempty" json:"paid_at,omitempty"` // Null until paid
	OverdueNotified bool              `bson:"overdue_notified" json:"overdue_notified"`   // Flag to prevent multiple overdue emails
	Deleted         bool              `bson:"deleted" json:"-"`                           // Soft delete flag
}
