package models

import (
	"time"

	"greendrake/l1/internal/utils"
)

// ValidationType defines the type of validation.
type ValidationType string

const (
	ValidationTypeDomainOwnership ValidationType = "domain_ownership"
	ValidationTypeOnlineProfile   ValidationType = "online_profile"
)

// UserValidationType represents a configurable type of user validation available.
// Stored in the `user_validation_types` collection.
type UserValidationType struct {
	ID         utils.SixID            `bson:"_id,omitempty" json:"id,omitempty"`
	Key        string                 `bson:"key" json:"key"` // e.g., "Domain Ownership", "eBay", "LinkedIn"
	Type       ValidationType         `bson:"type" json:"type"`
	Config     map[string]interface{} `bson:"config" json:"config"`           // YAML in DB, parsed to map[string]interface{}
	DataSchema map[string]interface{} `bson:"data_schema" json:"data_schema"` // JSON Schema for UserValidation.Data
	// Deleted     bool               `bson:"deleted" json:"-"`
}

// UserValidation represents an instance of a user attempting or completing a validation.
// Stored in the `user_validations` collection.
type UserValidation struct {
	ID             utils.SixID            `bson:"_id,omitempty" json:"id,omitempty"`
	UserID         utils.SixID            `bson:"user_id" json:"user_id"`
	TypeID         utils.SixID            `bson:"type_id" json:"type_id"`                 // Refers to UserValidationTypes collection
	ValidationType ValidationType         `bson:"validation_type" json:"validation_type"` // Denormalized from TypeID for easier querying?
	Data           map[string]interface{} `bson:"data" json:"data"`                       // Data specific to the validation type (e.g., {domain_name: "example.com"})
	ValueToProve   string                 `bson:"value_to_prove" json:"-"`                // Generated value user needs to place (e.g., <app_name>:ACCOUNT_VALIDATION:<_id>)
	ConfirmedAt    *time.Time             `bson:"confirmed_at,omitempty" json:"confirmed_at,omitempty"`
	RevokedAt      *time.Time             `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	Comments       string                 `bson:"comments,omitempty" json:"comments,omitempty"`
	CreatedAt      time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time              `bson:"updated_at" json:"updated_at"`
	Deleted        bool                   `bson:"deleted" json:"-"`
}
