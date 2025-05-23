package models

import (
	"greendrake/l1/internal/utils"
	"time"
)

// LinkedActionType defines the different types of actions confirmed via links/codes.
type LinkedActionType string

const (
	ActionLoginToSetupAccount    LinkedActionType = "login_to_setup_account"
	ActionEmailChangeOldApprove  LinkedActionType = "email_change_old_approve"
	ActionEmailChangeNewConfirm  LinkedActionType = "email_change_new_confirm"
	ActionPasswordReset          LinkedActionType = "password_reset"   // Maybe same as login_to_setup?
	ActionEmailLoginCode         LinkedActionType = "email_login_code" // For 2FA or email-only login
	ActionConfirmAccountDeletion LinkedActionType = "confirm_account_deletion"
	// Add other types as needed
)

// LinkedAction represents an action that needs to be confirmed, usually via email.
// The _id of this document is often used as the secret code in the link.
type LinkedAction struct {
	Base      `bson:",inline"`
	UserID    utils.SixID      `bson:"user_id" json:"user_id"`
	Type      LinkedActionType `bson:"type" json:"type"`
	CreatedAt time.Time        `bson:"created_at" json:"created_at"`
	ExpiresAt time.Time        `bson:"expires_at" json:"expires_at"`
	Executed  *time.Time       `bson:"executed,omitempty" json:"executed,omitempty"`
	// Data might hold action-specific info, e.g., new email for email_change
	Data    map[string]interface{} `bson:"data,omitempty" json:"data,omitempty"`
	Deleted bool                   `bson:"deleted" json:"-"` // Soft delete for cleanup?
}
