package models

import (
	"time"

	"greendrake/l1/internal/utils"
)

// AuthType defines the authentication methods available.
type AuthType string

const (
	AuthTypePasswordOnly              AuthType = "password_only"
	AuthTypeEmailLoginCodeOnly        AuthType = "email_login_code_only"
	AuthTypePasswordAndOTP            AuthType = "password_and_otp"
	AuthTypePasswordAndEmailLoginCode AuthType = "password_and_email_login_code"
	AuthTypeEmailLoginCodeAndOTP      AuthType = "email_login_code_and_otp"
	AuthTypeWebAuthn                  AuthType = "webauthn"
)

// EmailChange holds information about a pending email address change.
type EmailChange struct {
	NewAddress      string `bson:"new_address" json:"new_address"`
	ApprovedFromOld bool   `bson:"approved_from_old" json:"approved_from_old"`
	ConfirmedNew    bool   `bson:"confirmed_new" json:"confirmed_new"`
}

// DefaultListingSettings holds default values for new listings created by the user.
type DefaultListingSettings struct {
	Location utils.SixID `bson:"location,omitempty" json:"location,omitempty"`
	Shipping string      `bson:"shipping,omitempty" json:"shipping,omitempty"` // e.g., "pickup_only", "shipping_country_only", "shipping_worldwide"
}

// NotificationPreferences allows users to control email notifications.
type NotificationPreferences struct {
	Enquiry           bool `bson:"enquiry" json:"enquiry"`
	Offer             bool `bson:"offer" json:"offer"`
	UserSuspension    bool `bson:"user_suspension" json:"user_suspension"`
	ListingSuspension bool `bson:"listing_suspension" json:"listing_suspension"`
	InvoiceOverdue    bool `bson:"invoice_overdue" json:"invoice_overdue"`
}

// WebAuthnCredential represents a passkey credential for WebAuthn.
type WebAuthnCredential struct {
	CredentialID string    `bson:"credential_id" json:"credential_id"`
	PublicKey    string    `bson:"public_key" json:"public_key"`
	SignCount    uint32    `bson:"sign_count" json:"sign_count"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
}

// User represents a user in the system.
type User struct {
	Base                    `bson:",inline"`
	Name                    string                   `bson:"name" json:"name"`
	Email                   string                   `bson:"email" json:"email"`
	EmailChange             *EmailChange             `bson:"email_change,omitempty" json:"email_change,omitempty"`
	PasswordHash            string                   `bson:"password" json:"-"` // Store hash, not plaintext
	IsAdmin                 bool                     `bson:"is_admin" json:"is_admin"`
	Suspended               bool                     `bson:"suspended" json:"suspended"`
	Phantom                 bool                     `bson:"phantom" json:"phantom"`
	UpdatedAt               time.Time                `bson:"updated_at" json:"updated_at"`
	CreatedAt               time.Time                `bson:"created_at" json:"created_at"` // Assumed needed
	Overdue                 bool                     `bson:"overdue" json:"overdue"`
	AuthType                AuthType                 `bson:"auth_type" json:"auth_type"`
	Activated               bool                     `bson:"activated" json:"activated"`
	DefaultListingSettings  *DefaultListingSettings  `bson:"default_listing_settings,omitempty" json:"default_listing_settings,omitempty"`
	NotificationPreferences *NotificationPreferences `bson:"notification_preferences,omitempty" json:"notification_preferences,omitempty"`
	FreeTierListings        *int                     `bson:"free_tier_listings,omitempty" json:"free_tier_listings,omitempty"` // User-specific override
	Deleted                 bool                     `bson:"deleted" json:"-"`                                                 // Soft delete flag
	OTPSecret               string                   `bson:"otp_secret,omitempty" json:"otp_secret,omitempty"`
	WebAuthnCredentials     []WebAuthnCredential     `bson:"webauthn_credentials,omitempty" json:"webauthn_credentials,omitempty"`
}
