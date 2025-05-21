package models

import (
	"greendrake/l1/internal/utils"
)

// EmailTemplate defines the structure for email templates stored in the DB.
type EmailTemplate struct {
	ID         utils.SixID `bson:"_id,omitempty" json:"id,omitempty"`
	TemplateID string      `bson:"template_id" json:"template_id"` // e.g., "activate_account", "new_enquiry"
	Locale     string      `bson:"locale" json:"locale"`           // e.g., "en-US", "fr-FR"
	Subject    string      `bson:"subject" json:"subject"`         // Subject template
	Body       string      `bson:"body" json:"body"`               // Body template (plain text or HTML)
	// Deleted    bool               `bson:"deleted" json:"-"`
}
