package services

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/db"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
	"log"
	"strconv"
	"strings"
	"time"
)

// IListingService defines the interface for listing-related operations.
type IListingService interface {
	CreateListing(ctx context.Context, userID utils.SixID, title, body string, tags []string, locationID int, countryCode, shipping string, askingPrice *models.AskingPrice) (*models.Listing, error)
	FindListingByID(ctx context.Context, listingID utils.SixID) (*models.Listing, error)
	UpdateListing(ctx context.Context, listingID, userID utils.SixID, updates map[string]interface{}) (*models.Listing, error)
	PublishListing(ctx context.Context, listingID, userID utils.SixID) error
	HideListing(ctx context.Context, listingID, userID utils.SixID) error
	UnhideListing(ctx context.Context, listingID, userID utils.SixID) error
	DeleteListing(ctx context.Context, listingID, userID utils.SixID) error
	SearchListings(ctx context.Context, query *string, countryCode *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]models.Listing, string, error)
	AddImageToListing(ctx context.Context, listingID utils.SixID, imageKey string) error
	FindLatestListingByUserID(ctx context.Context, userID utils.SixID) (*models.Listing, error)
	// Listing suspension admin methods
	SuspendListing(ctx context.Context, listingID, adminUserID utils.SixID, reason string) error
	UnsuspendListing(ctx context.Context, listingID, adminUserID utils.SixID) error
	GetListingSuspension(ctx context.Context, listingID utils.SixID) (*models.ListingSuspension, error)
	ListSuspendedListings(ctx context.Context, limit int) ([]models.ListingSuspension, error)
	FindListingsByUserID(ctx context.Context, userID utils.SixID) ([]models.Listing, error)
	SearchListingsByUser(ctx context.Context, userID utils.SixID, query *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]*models.Listing, *string, error)
}

const listingsCollection = "listings"

// listingService implements IListingService.
type listingService struct {
	db  *mongo.Database
	cfg *config.Config
	// userService IUserService // May need user service to check defaults
}

// NewListingService creates a new ListingService.
func NewListingService(db *mongo.Database, cfg *config.Config /*, userService IUserService */) IListingService {
	return &listingService{db: db, cfg: cfg /*, userService: userService */}
}

// CreateListing creates a new listing document in a draft state.
func (s *listingService) CreateListing(ctx context.Context, userID utils.SixID, title, body string, tags []string, locationID int, countryCode, shipping string, askingPrice *models.AskingPrice) (*models.Listing, error) {
	collection := s.db.Collection(listingsCollection)
	now := time.Now().UTC()

	var newListing *models.Listing
	var err error

	operation := func() error {
		newListing = &models.Listing{
			ID:          utils.NewSixID(),
			UserID:      userID,
			Title:       title,
			Body:        body,
			Tags:        tags,
			Images:      []string{},
			LocationID:  locationID,
			CountryCode: countryCode,
			Shipping:    shipping,
			AskingPrice: askingPrice,
			IsDraft:     true,
			Phantom:     false,
			Hidden:      false,
			Deleted:     false,
			CreatedAt:   now,
			UpdatedAt:   now,
			PublishedAt: nil,
		}
		_, insertErr := collection.InsertOne(ctx, newListing)
		return insertErr
	}

	err = db.Try(operation)

	if err != nil {
		listingIDStr := "<unknown>"
		if newListing != nil {
			listingIDStr = newListing.ID.String()
		}
		return nil, fmt.Errorf("failed to insert new listing for user %s (last attempted listing ID: %s) after multiple retries: %w",
			userID.String(), listingIDStr, err)
	}

	return newListing, nil
}

// FindListingByID finds a non-deleted, non-suspended listing by its ID.
// It does NOT check ownership.
func (s *listingService) FindListingByID(ctx context.Context, listingID utils.SixID) (*models.Listing, error) {
	var listing models.Listing
	collection := s.db.Collection(listingsCollection)
	filter := bson.M{
		"_id":        listingID,
		"deleted":    false,
		"suspension": bson.M{"$exists": false}, // Ensure not suspended (SuspensionID is nil)
	}

	err := collection.FindOne(ctx, filter).Decode(&listing)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, mongo.ErrNoDocuments // Use standard error
		}
		return nil, fmt.Errorf("error finding listing by ID %s: %w", listingID.String(), err)
	}
	// Check for implicit suspension (user suspended or overdue)
	userColl := s.db.Collection("users")
	var user models.User
	err = userColl.FindOne(ctx, bson.M{"_id": listing.UserID, "deleted": false}).Decode(&user)
	if err != nil {
		return nil, mongo.ErrNoDocuments // Treat as not found if user not found
	}
	if user.Suspended || user.Overdue {
		return nil, mongo.ErrNoDocuments // Implicitly suspended
	}
	return &listing, nil
}

// UpdateListing updates mutable fields of a listing owned by the specified user.
// Only certain fields should be updatable (e.g., title, body, tags, price, location, shipping).
// Does not allow changing IsDraft, Hidden, etc. - use specific methods for those.
// `updates` map should contain BSON field names and new values.
func (s *listingService) UpdateListing(ctx context.Context, listingID, userID utils.SixID, updates map[string]interface{}) (*models.Listing, error) {
	collection := s.db.Collection(listingsCollection)

	// Ensure only allowed fields are updated (prevent changing ownership, status etc.)
	allowedUpdates := bson.M{}
	for key, value := range updates {
		switch key {
		case "title", "body", "tags", "location", "country_code", "shipping", "asking_price":
			allowedUpdates[key] = value
		default:
			return nil, fmt.Errorf("field '%s' cannot be updated via UpdateListing", key)
		}
	}
	if len(allowedUpdates) == 0 {
		return nil, fmt.Errorf("no valid fields provided for update")
	}
	allowedUpdates["updated_at"] = time.Now().UTC()

	filter := bson.M{
		"_id":        listingID,
		"user_id":    userID,
		"deleted":    false,
		"suspension": bson.M{"$exists": false}, // Listing must not be suspended to be updated
	}

	update := bson.M{"$set": allowedUpdates}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var updatedListing models.Listing
	err := collection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&updatedListing)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Could be not found, wrong user, deleted, or suspended
			return nil, fmt.Errorf("listing not found, not owned by user, or cannot be updated")
		}
		return nil, fmt.Errorf("failed to update listing %s: %w", listingID.String(), err)
	}

	return &updatedListing, nil
}

// updateListingStatus is a helper function to update listing status while checking conditions
func (s *listingService) updateListingStatus(ctx context.Context, listingID utils.SixID, userID utils.SixID, update bson.M) error {
	collection := s.db.Collection(listingsCollection)

	// Base filter checks ownership and not deleted
	filter := bson.M{
		"_id":     listingID,
		"user_id": userID,
		"deleted": false,
	}

	// Add suspension check if needed for operations that require a non-suspended listing
	// (e.g. hiding/unhiding implies it's not suspended, publishing implies not suspended)
	// This logic might vary based on the specific update operation.
	// For example, deleting a listing might be allowed even if suspended.
	// The caller function should construct the appropriate filter parts related to suspension.
	// For now, this specific check is removed from here and should be in calling functions if needed.
	// if update["$set"] != nil {
	// 	setDoc := update["$set"].(bson.M)
	// 	if _, ok := setDoc["hidden"]; ok { // Example: only apply suspension check when hiding/unhiding
	// 		filter["suspension"] = bson.M{"exists": false} // Corrected BSON field name
	// 	}
	// }

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error updating listing %s: %w", listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		// Check if listing exists
		// Use a simpler FindByID that doesn't have its own suspension checks for this internal check
		var listing models.Listing
		errCheck := collection.FindOne(ctx, bson.M{"_id": listingID}).Decode(&listing)
		if errors.Is(errCheck, mongo.ErrNoDocuments) {
			return fmt.Errorf("listing %s not found", listingID.String())
		}
		if listing.UserID != userID {
			return fmt.Errorf("listing %s does not belong to user %s", listingID.String(), userID.String())
		}
		if listing.Deleted {
			return fmt.Errorf("listing %s is deleted", listingID.String())
		}
		if listing.SuspensionID != nil { // Check if the pointer is not nil
			return fmt.Errorf("listing %s is suspended", listingID.String())
		}
		return fmt.Errorf("listing %s cannot be updated (already in desired state or other condition not met)", listingID.String())
	}

	return nil
}

// PublishListing publishes a draft listing
func (s *listingService) PublishListing(ctx context.Context, listingID utils.SixID, userID utils.SixID) error {
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"is_draft":     false,
			"published_at": now,
			"updated_at":   now,
		},
	}

	// Add filter to ensure listing is a draft and not suspended
	filter := bson.M{
		"_id":        listingID,
		"user_id":    userID,
		"deleted":    false,
		"is_draft":   true,
		"suspension": bson.M{"$exists": false}, // Ensure not suspended (SuspensionID is nil)
	}

	collection := s.db.Collection(listingsCollection)
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error publishing listing %s: %w", listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		// Check why it couldn't be published
		var listing models.Listing
		checkErr := s.db.Collection(listingsCollection).FindOne(ctx, bson.M{"_id": listingID}).Decode(&listing)
		if errors.Is(checkErr, mongo.ErrNoDocuments) {
			return fmt.Errorf("listing %s not found", listingID.String())
		}
		if listing.UserID != userID {
			return fmt.Errorf("listing %s does not belong to user %s", listingID.String(), userID.String())
		}
		if listing.Deleted {
			return fmt.Errorf("listing %s is deleted", listingID.String())
		}
		if listing.SuspensionID != nil {
			return fmt.Errorf("listing %s is suspended", listingID.String())
		}
		if !listing.IsDraft {
			return fmt.Errorf("listing %s is already published or not a draft", listingID.String())
		}
		return fmt.Errorf("failed to publish listing %s (condition not met)", listingID.String())
	}

	// TODO: Trigger billing start logic
	return nil
}

// HideListing hides a published listing
func (s *listingService) HideListing(ctx context.Context, listingID utils.SixID, userID utils.SixID) error {
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"hidden":     true,
			"hidden_at":  now,
			"updated_at": now,
		},
	}

	// Add filter to ensure listing is published, not hidden, and not suspended
	filter := bson.M{
		"_id":        listingID,
		"user_id":    userID,
		"deleted":    false,
		"is_draft":   false,
		"hidden":     false,
		"suspension": bson.M{"$exists": false}, // Ensure not suspended (SuspensionID is nil)
	}

	collection := s.db.Collection(listingsCollection)
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error hiding listing %s: %w", listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		var listing models.Listing
		checkErr := s.db.Collection(listingsCollection).FindOne(ctx, bson.M{"_id": listingID}).Decode(&listing)
		if errors.Is(checkErr, mongo.ErrNoDocuments) {
			return fmt.Errorf("listing %s not found", listingID.String())
		}
		if listing.UserID != userID {
			return fmt.Errorf("listing %s does not belong to user %s", listingID.String(), userID.String())
		}
		if listing.Deleted {
			return fmt.Errorf("listing %s is deleted", listingID.String())
		}
		if listing.SuspensionID != nil {
			return fmt.Errorf("listing %s is suspended", listingID.String())
		}
		if listing.IsDraft {
			return fmt.Errorf("listing %s is still a draft", listingID.String())
		}
		if listing.Hidden {
			return fmt.Errorf("listing %s is already hidden", listingID.String())
		}
		return fmt.Errorf("failed to hide listing %s (condition not met)", listingID.String())
	}

	// TODO: Trigger billing stop logic
	return nil
}

// UnhideListing unhides a hidden listing
func (s *listingService) UnhideListing(ctx context.Context, listingID utils.SixID, userID utils.SixID) error {
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"hidden":     false,
			"updated_at": now,
		},
		"$unset": bson.M{
			"hidden_at": "",
		},
	}

	// Add filter to ensure listing is published, hidden, and not suspended
	filter := bson.M{
		"_id":        listingID,
		"user_id":    userID,
		"deleted":    false,
		"is_draft":   false,
		"hidden":     true,
		"suspension": bson.M{"$exists": false}, // Ensure not suspended (SuspensionID is nil)
	}

	collection := s.db.Collection(listingsCollection)
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error unhiding listing %s: %w", listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		var listing models.Listing
		checkErr := s.db.Collection(listingsCollection).FindOne(ctx, bson.M{"_id": listingID}).Decode(&listing)
		if errors.Is(checkErr, mongo.ErrNoDocuments) {
			return fmt.Errorf("listing %s not found", listingID.String())
		}
		if listing.UserID != userID {
			return fmt.Errorf("listing %s does not belong to user %s", listingID.String(), userID.String())
		}
		if listing.Deleted {
			return fmt.Errorf("listing %s is deleted", listingID.String())
		}
		if listing.SuspensionID != nil {
			return fmt.Errorf("listing %s is suspended", listingID.String())
		}
		if listing.IsDraft {
			return fmt.Errorf("listing %s is still a draft", listingID.String())
		}
		if !listing.Hidden {
			return fmt.Errorf("listing %s is not hidden", listingID.String())
		}
		return fmt.Errorf("failed to unhide listing %s (condition not met)", listingID.String())
	}

	// TODO: Trigger billing start logic
	return nil
}

// DeleteListing performs a soft delete by setting the deleted flag to true.
func (s *listingService) DeleteListing(ctx context.Context, listingID, userID utils.SixID) error {
	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"deleted":    true,
			"deleted_at": now,
			"updated_at": now,
		},
	}
	return s.updateListingStatus(ctx, listingID, userID, update)
}

// SearchListings searches listings based on various criteria.
func (s *listingService) SearchListings(ctx context.Context, query *string, countryCode *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]models.Listing, string, error) {
	collection := s.db.Collection(listingsCollection)

	filter := bson.M{
		"is_draft":   false,
		"hidden":     false,
		"deleted":    false,
		"suspension": bson.M{"$exists": false},
	}

	// Text search
	if query != nil && *query != "" {
		filter["$text"] = bson.M{"search": *query}
	}

	// Country filter
	if countryCode != nil {
		filter["country_code"] = *countryCode
	}

	// Tag filtering
	includeTags := []string{}
	excludeTags := []string{}
	for _, tag := range tags {
		if strings.HasPrefix(tag, "-") && len(tag) > 1 {
			excludeTags = append(excludeTags, strings.TrimPrefix(tag, "-"))
		} else if !strings.HasPrefix(tag, "-") && tag != "" {
			includeTags = append(includeTags, tag)
		}
	}
	if len(includeTags) > 0 || len(excludeTags) > 0 {
		tagFilter := bson.M{}
		if len(includeTags) > 0 {
			tagFilter["all"] = includeTags
		}
		if len(excludeTags) > 0 {
			tagFilter["nin"] = excludeTags
		}
		filter["tags"] = tagFilter
	}

	// Geo filtering ($geoWithin)
	if nearLocation != nil && maxDistanceKM != nil && *maxDistanceKM > 0 {
		maxDistanceMeters := float64(*maxDistanceKM * 1000)
		filter["location"] = bson.M{
			"$nearSphere": bson.M{
				"$geometry": bson.M{
					"type":        "Point",
					"coordinates": nearLocation.Coordinates,
				},
				"$maxDistance": maxDistanceMeters,
			},
		}
		// Note: $nearSphere implies sorting by distance, but we handle explicit sort below.
		// If only filtering is needed, $geoWithin with $centerSphere is an alternative.
	}

	// --- Pagination & Sorting ---
	opts := options.Find()
	opts.SetLimit(int64(limit + 1))

	// Sorting logic
	sort := bson.D{}
	projection := bson.D{}

	if sortBy == "proximity" && nearLocation != nil {
		// $geoNear aggregation is the proper way to sort by distance.
		// Since we are using Find() for simplicity with $text search,
		// we cannot truly sort by calculated distance here.
		// The $nearSphere filter implicitly orders by distance, but combining with other sorts is tricky.
		// We will rely on the implicit $nearSphere ordering when geo filter is active.
		log.Println("WARN: Explicit proximity sort with Find() is limited; results are implicitly ordered by distance when geo-filtering.")
		// No explicit sort added here if $nearSphere is used.
	} else if query != nil && *query != "" && (sortBy == "" || sortBy == "relevance") {
		projection = append(projection, bson.E{Key: "score", Value: bson.M{"meta": "textScore"}})
		sort = append(sort, bson.E{Key: "score", Value: bson.M{"meta": "textScore"}})
	} else if sortBy == "date" {
		sort = append(sort, bson.E{Key: "published_at", Value: -1})
	} else {
		// Default sort (newest first) if no other sort criteria match
		sort = append(sort, bson.E{Key: "published_at", Value: -1})
	}

	if len(sort) > 0 {
		opts.SetSort(sort)
	}
	if len(projection) > 0 {
		opts.SetProjection(projection)
	}

	// Cursor handling - Using `published_at` and `_id` for stable pagination
	if cursor != nil && *cursor != "" {
		parts := strings.Split(*cursor, "_")
		if len(parts) == 2 {
			timestampSec, tsErr := strconv.ParseInt(parts[0], 10, 64)
			lastID, idErr := utils.ParseSixID(parts[1])
			if tsErr == nil && idErr == nil {
				cursorTime := time.Unix(timestampSec, 0)
				// Apply filter based on sort order (assuming published_at desc)
				// Find items published at the same time but with smaller ID, OR items published earlier.
				filter["$or"] = bson.A{
					bson.M{"published_at": cursorTime, "_id": bson.M{"lt": lastID}},
					bson.M{"published_at": bson.M{"lt": cursorTime}},
				}
				// TODO: Adapt cursor logic if sort order changes (e.g., relevance, proximity)
			} else {
				log.Printf("WARN: Invalid cursor format received: %s", *cursor)
			}
		} else {
			log.Printf("WARN: Invalid cursor format received: %s", *cursor)
		}
	}

	// Execute query
	listCursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, "", fmt.Errorf("failed to execute listing search query: %w", err)
	}
	defer listCursor.Close(ctx)

	var results []models.Listing
	if err = listCursor.All(ctx, &results); err != nil {
		return nil, "", fmt.Errorf("failed to decode listing search results: %w", err)
	}

	// Post-filter for implicit suspension (user suspended/overdue)
	userColl := s.db.Collection("users")
	filtered := make([]models.Listing, 0, len(results))
	for _, l := range results {
		var user models.User
		err := userColl.FindOne(ctx, bson.M{"_id": l.UserID, "deleted": false}).Decode(&user)
		if err != nil || user.Suspended || user.Overdue {
			continue // Skip implicitly suspended
		}
		filtered = append(filtered, l)
	}

	// Determine next cursor based on last item and sort order (published_at desc)
	nextCursor := ""
	if len(filtered) > limit {
		lastItem := filtered[limit-1]
		if lastItem.PublishedAt != nil {
			nextCursor = fmt.Sprintf("%d_%s", lastItem.PublishedAt.Unix(), lastItem.ID.String())
		}
		filtered = filtered[:limit]
	}

	return filtered, nextCursor, nil
}

// AddImageToListing adds a processed image key to a listing's image array.
// It should only be called after the image processing task is complete.
func (s *listingService) AddImageToListing(ctx context.Context, listingID utils.SixID, imageKey string) error {
	collection := s.db.Collection(listingsCollection)

	filter := bson.M{
		"_id":     listingID,
		"deleted": false,
		// Maybe check if it's suspended?
	}
	update := bson.M{
		"$addToSet": bson.M{"images": imageKey}, // Add key if not already present
		"$set":      bson.M{"updated_at": time.Now().UTC()},
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("db error adding image %s to listing %s: %w", imageKey, listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		// Listing not found or was deleted/suspended?
		return fmt.Errorf("listing %s not found or cannot be updated when adding image", listingID.String())
	}
	if result.ModifiedCount == 0 {
		// Image key might already exist in the array
		fmt.Printf("Image key %s likely already exists for listing %s\n", imageKey, listingID.String())
	}

	return nil
}

// FindLatestListingByUserID finds the most recently updated listing for a specific user.
// Returns the listing or mongo.ErrNoDocuments if none found.
func (s *listingService) FindLatestListingByUserID(ctx context.Context, userID utils.SixID) (*models.Listing, error) {
	var listing models.Listing
	collection := s.db.Collection(listingsCollection)
	filter := bson.M{"user_id": userID, "deleted": false}
	// Sort by updated_at descending, limit 1
	opts := options.FindOne().SetSort(bson.D{{Key: "updated_at", Value: -1}})

	err := collection.FindOne(ctx, filter, opts).Decode(&listing)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, mongo.ErrNoDocuments
		}
		return nil, fmt.Errorf("error finding latest listing for user %s: %w", userID.String(), err)
	}
	return &listing, nil
}

// SuspendListing creates a suspension record and marks the listing as suspended.
func (s *listingService) SuspendListing(ctx context.Context, listingID, adminUserID utils.SixID, reason string) error {
	// First, check if the listing exists and is not already suspended
	listingCollection := s.db.Collection(listingsCollection)
	var existingListing models.Listing
	filter := bson.M{
		"_id":        listingID,
		"deleted":    false,
		"suspension": bson.M{"$exists": false}, // Check if not already suspended
	}
	err := listingCollection.FindOne(ctx, filter).Decode(&existingListing)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// To give a more specific error, we can query without the suspension check
			checkFilter := bson.M{"_id": listingID, "deleted": false}
			var checkListing models.Listing
			if checkErr := listingCollection.FindOne(ctx, checkFilter).Decode(&checkListing); checkErr == nil {
				if checkListing.SuspensionID != nil {
					return fmt.Errorf("listing %s is already suspended", listingID.String())
				}
			}
			return fmt.Errorf("listing %s not found, deleted, or already suspended", listingID.String())
		}
		return fmt.Errorf("failed to find listing %s for suspension: %w", listingID.String(), err)
	}

	suspColl := s.db.Collection("listing_suspensions")
	now := time.Now().UTC()

	var susp models.ListingSuspension // Defined to be captured by the closure
	// err is reused from the FindOne operation above for the suspension insertion operation

	operation := func() error {
		suspensionID := utils.NewSixID() // ID generated on each attempt for the suspension record
		susp = models.ListingSuspension{
			ID:         suspensionID,
			ListingID:  listingID,
			UserID:     adminUserID,
			Reason:     reason,
			ExecutedAt: &now,
			Suspended:  true,
		}
		_, insertErr := suspColl.InsertOne(ctx, susp)
		return insertErr
	}

	err = db.Try(operation)

	if err != nil {
		suspensionIDStr := "<unknown>"
		if susp.ID != (utils.SixID{}) {
			suspensionIDStr = susp.ID.String()
		}
		return fmt.Errorf("failed to create listing suspension record for listing %s (last attempted suspension ID: %s) after multiple retries: %w",
			listingID.String(), suspensionIDStr, err)
	}

	// Update the main listing document with the new suspension_id
	update := bson.M{"$set": bson.M{
		"suspension": susp.ID,
		"updated_at": now,
		"hidden":     true,
	}}
	_, updateErr := listingCollection.UpdateByID(ctx, listingID, update)
	if updateErr != nil {
		log.Printf("CRITICAL: Suspension record %s created for listing %s, but failed to update listing: %v", susp.ID.String(), listingID.String(), updateErr)
		return fmt.Errorf("failed to update listing %s with suspension ID %s: %w", listingID.String(), susp.ID.String(), updateErr)
	}

	return nil
}

// UnsuspendListing removes the suspension from a listing.
func (s *listingService) UnsuspendListing(ctx context.Context, listingID, adminUserID utils.SixID) error {
	collection := s.db.Collection(listingsCollection)
	suspColl := s.db.Collection("listing_suspensions")
	var listing models.Listing
	// Find the listing to get its current SuspensionID (which refers to the _id in listing_suspensions)
	err := collection.FindOne(ctx, bson.M{"_id": listingID, "deleted": false}).Decode(&listing)
	if err != nil {
		// If no documents, or other error, the listing isn't findable or suitable for unsuspend.
		return fmt.Errorf("listing %s not found or already deleted: %w", listingID.String(), err)
	}

	if listing.SuspensionID == nil { // Check if the pointer is nil
		return fmt.Errorf("listing %s is not currently suspended", listingID.String())
	}

	// Mark the specific suspension record as not active (e.g., set Suspended to false or soft delete it)
	// Here, we mark the specific ListingSuspension document as no longer active.
	// The model has `Suspended bool` and `Deleted bool`.
	// Let's set Suspended = false and Deleted = true for the old suspension record.
	suspUpdate := bson.M{
		"$set": bson.M{
			"suspended":  false,
			"deleted":    true,             // Or just mark as not suspended and keep for history
			"updated_at": time.Now().UTC(), // Assuming ListingSuspension has an UpdatedAt field
		},
	}
	// Dereference listing.SuspensionID when using it as a value in the filter
	_, err = suspColl.UpdateOne(ctx, bson.M{"_id": *listing.SuspensionID}, suspUpdate)
	if err != nil {
		// Log this error, as it's important, but proceed to try and update the main listing if possible
		// Dereference for logging, protected by earlier nil check
		log.Printf("Warning: failed to update listing_suspensions record %s for listing %s during unsuspend: %v", (*listing.SuspensionID).String(), listingID.String(), err)
	}

	// Remove suspension from listing by unsetting the 'suspension' field
	listingUpdate := bson.M{
		"$unset": bson.M{"suspension": ""},
		"$set":   bson.M{"updated_at": time.Now().UTC()},
	}
	result, err := collection.UpdateOne(ctx, bson.M{"_id": listingID}, listingUpdate)
	if err != nil {
		return fmt.Errorf("failed to update listing %s to remove suspension: %w", listingID.String(), err)
	}
	if result.MatchedCount == 0 {
		// This shouldn't happen if the initial FindOne succeeded, but as a safeguard:
		return fmt.Errorf("listing %s not found during final update for unsuspend", listingID.String())
	}
	log.Printf("Listing %s unsuspended by admin %s.", listingID.String(), adminUserID.String())
	return nil
}

// GetListingSuspension fetches the active suspension record for a listing.
func (s *listingService) GetListingSuspension(ctx context.Context, listingID utils.SixID) (*models.ListingSuspension, error) {
	suspColl := s.db.Collection("listing_suspensions")
	var susp models.ListingSuspension
	// Find the active suspension record for the given listingID
	// The Listing model stores the ID of its current suspension in the 'suspension' field.
	// So, we first need to get the listing to find its current suspension ID.
	var listing models.Listing
	listingCollection := s.db.Collection(listingsCollection)
	err := listingCollection.FindOne(ctx, bson.M{"_id": listingID, "deleted": false}).Decode(&listing)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("listing %s not found", listingID.String())
		}
		return nil, fmt.Errorf("error fetching listing %s to get suspension details: %w", listingID.String(), err)
	}

	if listing.SuspensionID == nil { // No active suspension ID on the listing
		return nil, mongo.ErrNoDocuments // Or a more specific "not suspended" error
	}

	// Now fetch the actual suspension record using the ID from the listing
	// Dereference listing.SuspensionID when using it as a value in the filter
	err = suspColl.FindOne(ctx, bson.M{"_id": *listing.SuspensionID, "deleted": false, "suspended": true}).Decode(&susp)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// This case implies an inconsistency if listing.SuspensionID was set but no matching active record found.
			// Dereference for logging, protected by earlier nil check
			log.Printf("Warning: Listing %s has SuspensionID %s but no matching active suspension record found.", listingID.String(), (*listing.SuspensionID).String())
		}
		return nil, err // Propagate the error (e.g., ErrNoDocuments or DB error)
	}
	return &susp, nil
}

// ListSuspendedListings returns a list of currently suspended listings (for admin review).
func (s *listingService) ListSuspendedListings(ctx context.Context, limit int) ([]models.ListingSuspension, error) {
	suspColl := s.db.Collection("listing_suspensions")
	filter := bson.M{"deleted": false, "suspended": true}
	opts := options.Find().SetLimit(int64(limit)).SetSort(bson.D{{Key: "executed", Value: -1}})
	cursor, err := suspColl.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var results []models.ListingSuspension
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// FindListingsByUserID returns all visible listings for a user, only if the user is not suspended/overdue.
func (s *listingService) FindListingsByUserID(ctx context.Context, userID utils.SixID) ([]models.Listing, error) {
	userColl := s.db.Collection("users")
	var user models.User
	err := userColl.FindOne(ctx, bson.M{"_id": userID, "deleted": false}).Decode(&user)
	if err != nil || user.Suspended || user.Overdue {
		return nil, mongo.ErrNoDocuments
	}
	coll := s.db.Collection(listingsCollection)
	filter := bson.M{"user_id": userID, "deleted": false, "hidden": false, "suspension": bson.M{"$exists": false}, "is_draft": false}
	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var listings []models.Listing
	if err = cursor.All(ctx, &listings); err != nil {
		return nil, err
	}
	return listings, nil
}

// SearchListingsByUser searches listings based on various criteria for a specific user.
func (s *listingService) SearchListingsByUser(ctx context.Context, userID utils.SixID, query *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]*models.Listing, *string, error) {
	filter := bson.M{
		"user_id":    userID,
		"deleted":    false,
		"suspension": bson.M{"$exists": false}, // Exclude suspended listings
	}
	if query != nil && *query != "" {
		filter["$text"] = bson.M{"$search": *query}
	}
	if len(tags) > 0 {
		filter["tags"] = bson.M{"$all": tags}
	}
	if nearLocation != nil && maxDistanceKM != nil {
		filter["location"] = bson.M{"$near": bson.M{
			"$geometry":    nearLocation,
			"$maxDistance": *maxDistanceKM * 1000, // meters
		}}
	}
	// TODO: Add cursor-based pagination logic
	opts := options.Find().SetLimit(int64(limit))
	// Sorting
	switch sortBy {
	case "date_desc":
		opts.SetSort(bson.D{{"updated_at", -1}})
	case "date_asc":
		opts.SetSort(bson.D{{"updated_at", 1}})
		// Add more sort options as needed
	}
	cur, err := s.db.Collection(listingsCollection).Find(ctx, filter, opts)
	if err != nil {
		return nil, nil, err
	}
	defer cur.Close(ctx)
	var listings []*models.Listing
	for cur.Next(ctx) {
		var l models.Listing
		if err := cur.Decode(&l); err != nil {
			return nil, nil, err
		}
		listings = append(listings, &l)
	}
	// TODO: Implement nextCursor for pagination
	return listings, nil, nil
}

// TODO: Implement other listing service methods...
