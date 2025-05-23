package services

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// IEnquiryService defines the interface for enquiry operations.
type IEnquiryService interface {
	CreateEnquiry(ctx context.Context, listingID utils.SixID, userID *utils.SixID, userEmail, message string, offer *models.AskingPrice) (*models.ListingEnquiry, error)
	// MarkEnquirySent(ctx context.Context, enquiryID utils.SixID) error
}

const enquiriesCollection = "listing_enquiries"

// enquiryService implements IEnquiryService.
type enquiryService struct {
	db  *mongo.Database
	cfg *config.Config
	// listingService IListingService // May need to check listing exists/is active
}

// NewEnquiryService creates a new EnquiryService.
func NewEnquiryService(db *mongo.Database, cfg *config.Config /*, listingService IListingService */) IEnquiryService {
	return &enquiryService{db: db, cfg: cfg /*, listingService: listingService*/}
}

// CreateEnquiry creates a new enquiry document.
func (s *enquiryService) CreateEnquiry(ctx context.Context, listingID utils.SixID, userID *utils.SixID, userEmail, message string, offer *models.AskingPrice) (*models.ListingEnquiry, error) {
	// Basic validation: message or offer must be present
	if message == "" && offer == nil {
		return nil, fmt.Errorf("enquiry must have a message or an offer")
	}
	// TODO: Validate email format?
	// TODO: Check if listingID exists and is active/visible using listingService?

	now := time.Now().UTC()

	doc, err := db.InsertOne(ctx, s.db.Collection(enquiriesCollection), &models.ListingEnquiry{
		ListingID: listingID,
		UserEmail: userEmail,
		Message:   message,
		UserID:    *userID,
		Offer:     offer,
		CreatedAt: now,
		Sent:      false, // Email sending handled by background task
		Deleted:   false,
	})
	return doc.(*models.ListingEnquiry), err
}

// TODO: Implement MarkEnquirySent used by background task
