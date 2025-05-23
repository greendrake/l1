package services

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// IBillingService defines the interface for billing operations.
type IBillingService interface {
	CalculateChargesForUser(ctx context.Context, userID utils.SixID) (float64, []models.InvoiceLineItem, error) // Calculate outstanding charges
	GenerateInvoice(ctx context.Context, userID utils.SixID, items []models.InvoiceLineItem, subtotal float64, currencyCode string) (*models.Invoice, error)
	FindOverdueInvoices(ctx context.Context) ([]models.Invoice, error)
	MarkInvoiceOverdueNotified(ctx context.Context, invoiceID utils.SixID) error
	// CheckAndMarkOverdue(ctx context.Context) error // Background task logic
}

const (
	invoicesCollection = "invoices"
	// listingsCollection is already defined in listing_service
)

// billingService implements IBillingService.
type billingService struct {
	db             *mongo.Database
	cfg            *config.Config
	configService  IConfigService  // Needed for billing params like BASE_RATE, BASE_PERIOD_DAYS
	listingService IListingService // Needed to find user's listings
	userService    IUserService    // Needed for user's free tier info
}

// NewBillingService creates a new BillingService.
func NewBillingService(db *mongo.Database, cfg *config.Config, configService IConfigService, listingService IListingService, userService IUserService) IBillingService {
	return &billingService{
		db:             db,
		cfg:            cfg,
		configService:  configService,
		listingService: listingService,
		userService:    userService,
	}
}

// Need GetFloat64 helper in ConfigService or implement here
func (s *billingService) getFloat64Config(ctx context.Context, key string, defaultValue float64) float64 {
	val, err := s.configService.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	default:
		log.Printf("Warning: Config key '%s' is not a float64 type (%T), using default.", key, val)
		return defaultValue
	}
}

// CalculateChargesForUser calculates the total outstanding, uninvoiced charges for a user.
// It returns the total amount, the line items making up the charge, and any error.
func (s *billingService) CalculateChargesForUser(ctx context.Context, userID utils.SixID) (float64, []models.InvoiceLineItem, error) {
	// 1. Get billing parameters
	baseRate := s.getFloat64Config(ctx, "BASE_RATE", s.cfg.BaseRate) // Use helper
	basePeriodDays := s.configService.GetInt(ctx, "BASE_PERIOD_DAYS", s.cfg.BasePeriodDays)
	if basePeriodDays <= 0 {
		return 0, nil, fmt.Errorf("invalid BASE_PERIOD_DAYS configuration")
	}
	basePeriodDuration := time.Duration(basePeriodDays*24) * time.Hour

	// 2. Get user's free tier allowance
	user, err := s.userService.FindByID(ctx, userID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to find user %s for billing calc: %w", userID.String(), err)
	}
	freeTier := s.cfg.FreeTierListings // Default
	if user.FreeTierListings != nil {  // Check for user override
		freeTier = *user.FreeTierListings
	}
	if freeTier < 0 {
		freeTier = 0
	}

	// 3. Find all active (published, not deleted, not suspended) listings for the user
	// TODO: Need a listing service method to find listings by user with specific statuses
	// listings, err := s.listingService.FindActiveListingsByUser(ctx, userID)
	// if err != nil { ... }
	listings := []models.Listing{} // Placeholder
	fmt.Printf("[TODO] Need ListingService.FindActiveListingsByUser for billing calc (User: %s)\n", userID.String())

	// 4. Find the last billing date for each listing (from previous invoices)
	lastBilledUntil := make(map[utils.SixID]time.Time)
	// invoiceItemsFilter := bson.M{ // Removed
	// 	"user_id": userID,
	// }
	// TODO: Efficiently get the latest 'billed_until' for each listing_id
	fmt.Printf("[TODO] Need to query latest billed_until date per listing for billing calc (User: %s)\n", userID.String())

	// 5. Calculate charges for each listing
	totalCharge := 0.0
	lineItems := []models.InvoiceLineItem{}
	sort.Slice(listings, func(i, j int) bool { // Process oldest first to apply free tier correctly
		return listings[i].PublishedAt.Before(*listings[j].PublishedAt)
	})

	activePaidListingCount := 0
	now := time.Now().UTC()

	for _, listing := range listings {
		if listing.PublishedAt == nil {
			continue
		} // Skip drafts just in case

		// Apply free tier
		if activePaidListingCount < freeTier {
			activePaidListingCount++
			continue // This listing is free
		}

		// Calculate billing period for this paid listing
		chargeableSince := *listing.PublishedAt
		if lastBillDate, ok := lastBilledUntil[listing.ID]; ok {
			chargeableSince = lastBillDate // Start charging from the day after last billed date
		}

		chargeableDuration := now.Sub(chargeableSince)
		if chargeableDuration <= 0 {
			continue // Not yet time to charge again / already billed up to now
		}

		// Calculate number of base periods (rounded up)
		numPeriods := math.Ceil(chargeableDuration.Hours() / basePeriodDuration.Hours())
		if numPeriods <= 0 {
			continue
		}

		charge := numPeriods * baseRate
		billedUntil := chargeableSince.Add(time.Duration(numPeriods) * basePeriodDuration)

		lineItems = append(lineItems, models.InvoiceLineItem{
			ListingID:    listing.ID,
			ListingTitle: listing.Title,
			StartDate:    chargeableSince,
			BilledUntil:  billedUntil,
			Amount:       charge,
		})
		totalCharge += charge
	}

	// TODO: Consider currency handling/conversion if BASE_RATE has a currency
	return totalCharge, lineItems, nil
}

// GenerateInvoice creates a new invoice document.
func (s *billingService) GenerateInvoice(ctx context.Context, userID utils.SixID, items []models.InvoiceLineItem, subtotal float64, currencyCode string) (*models.Invoice, error) {
	// TODO: Tax calculation
	tax := 0.0
	total := subtotal + tax

	// TODO: Get invoice due date parameters from config
	now := time.Now().UTC()
	dueDuration := time.Duration(s.cfg.InvoicePaymentWaitTimeDays*24) * time.Hour
	dueAt := now.Add(dueDuration)

	// TODO: Generate unique invoice number
	invoiceNumber := fmt.Sprintf("INV-%s-%d", userID.String()[len(userID.String())-4:], now.Unix())

	doc, err := db.InsertOne(ctx, s.db.Collection(invoicesCollection), &models.Invoice{
		UserID:          userID,
		InvoiceNumber:   invoiceNumber, // Invoice number can remain the same for retries, or be regenerated too if needed
		Items:           items,
		CurrencyCode:    currencyCode,
		Subtotal:        subtotal,
		Tax:             tax,
		Total:           total,
		IssuedAt:        now,
		DueAt:           dueAt,
		Sent:            false,
		PaidAt:          nil,
		OverdueNotified: false,
		Deleted:         false,
	})
	return doc.(*models.Invoice), err
}

// FindOverdueInvoices retrieves all invoices that are past their due date and not yet paid.
func (s *billingService) FindOverdueInvoices(ctx context.Context) ([]models.Invoice, error) {
	collection := s.db.Collection(invoicesCollection)
	now := time.Now().UTC()
	filter := bson.M{
		"due":     bson.M{"lt": now},
		"paid_at": nil,
		"deleted": false,
	}
	// Optionally add: "overdue_notified": false to only fetch those not yet processed?

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query overdue invoices: %w", err)
	}
	defer cursor.Close(ctx)

	var invoices []models.Invoice
	if err = cursor.All(ctx, &invoices); err != nil {
		return nil, fmt.Errorf("failed to decode overdue invoices: %w", err)
	}
	return invoices, nil
}

// MarkInvoiceOverdueNotified sets the OverdueNotified flag on an invoice.
func (s *billingService) MarkInvoiceOverdueNotified(ctx context.Context, invoiceID utils.SixID) error {
	collection := s.db.Collection(invoicesCollection)
	filter := bson.M{"_id": invoiceID}
	update := bson.M{"set": bson.M{"overdue_notified": true}}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error marking invoice %s overdue notified: %w", invoiceID.String(), err)
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments // Invoice not found
	}
	return nil
}
