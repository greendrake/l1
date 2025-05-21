package handlers_test

import (
	// "context"
	"encoding/json"
	// "errors"
	// "fmt"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/api/handlers"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/utils"
)

// --- Mocks Removed (Now in mocks_test.go) ---

// --- Tests ---

func TestRestListingHandler_GetListingByID_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockListingSvc := new(MockListingService) // Assumes MockListingService is defined in mocks_test.go
	handler := handlers.NewRestListingHandler(mockListingSvc)

	r := gin.New()
	r.GET("/v1/listing/:id", handler.GetListingByID)

	listingID := utils.NewSixID()
	expectedListing := &models.Listing{
		ID:          listingID,
		Title:       "Test Item",
		Body:        "Description here",
		CountryCode: "CA",
		IsDraft:     false,
	}
	mockListingSvc.On("FindListingByID", mock.Anything, listingID).Return(expectedListing, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/listing/"+listingID.String(), nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody models.Listing
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedListing.ID, respBody.ID)
	assert.Equal(t, expectedListing.Title, respBody.Title)
	mockListingSvc.AssertExpectations(t)
}

func TestRestListingHandler_GetListingByID_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockListingSvc := new(MockListingService) // Assumes defined elsewhere
	handler := handlers.NewRestListingHandler(mockListingSvc)

	r := gin.New()
	r.GET("/v1/listing/:id", handler.GetListingByID)

	listingID := utils.NewSixID()
	mockListingSvc.On("FindListingByID", mock.Anything, listingID).Return(nil, mongo.ErrNoDocuments)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/listing/"+listingID.String(), nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Contains(t, respBody["error"], "Listing not found")
	mockListingSvc.AssertExpectations(t)
}

func TestRestListingHandler_SearchListings_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockListingSvc := new(MockListingService) // Assumes defined elsewhere
	handler := handlers.NewRestListingHandler(mockListingSvc)

	r := gin.New()
	r.GET("/v1/listing/search", handler.SearchListings)

	query := "bike"
	limit := 10
	expectedListings := []models.Listing{
		{ID: utils.NewSixID(), Title: "Mountain Bike"},
		{ID: utils.NewSixID(), Title: "Road Bike"},
	}
	expectedCursor := "nextpagecursor"

	mockListingSvc.On("SearchListings", mock.Anything, &query, (*string)(nil), []string(nil), (*models.GeoJSON)(nil), (*int)(nil), limit, (*string)(nil), "").Return(expectedListings, expectedCursor, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/listing/search?q=bike&limit=10", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedCursor, respBody["next_cursor"])
	data, ok := respBody["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 2)
	mockListingSvc.AssertExpectations(t)
}

func TestRestListingHandler_SearchListings_WithTags(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockListingSvc := new(MockListingService)
	handler := handlers.NewRestListingHandler(mockListingSvc)
	r := gin.New()
	r.GET("/v1/listing/search", handler.SearchListings)

	limit := 5
	tags := []string{"road", "-carbon"}
	expectedListings := []models.Listing{ /* ... listings matching tags ... */ }

	mockListingSvc.On("SearchListings", mock.Anything, (*string)(nil), (*string)(nil), tags, (*models.GeoJSON)(nil), (*int)(nil), limit, (*string)(nil), "").Return(expectedListings, "", nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/listing/search?tags=road,-carbon&limit=5", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// ... assert response body ...
	mockListingSvc.AssertExpectations(t)
}

func TestRestListingHandler_SearchListings_WithGeo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockListingSvc := new(MockListingService)
	handler := handlers.NewRestListingHandler(mockListingSvc)
	r := gin.New()
	r.GET("/v1/listing/search", handler.SearchListings)

	limit := 20
	lat := 40.7128
	lon := -74.0060
	dist := 5 // 5km
	expectedNear := &models.GeoJSON{Type: "Point", Coordinates: []float64{lon, lat}}
	expectedListings := []models.Listing{ /* ... listings within 5km ... */ }

	mockListingSvc.On("SearchListings", mock.Anything, (*string)(nil), (*string)(nil), []string(nil), expectedNear, &dist, limit, (*string)(nil), "").Return(expectedListings, "", nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", fmt.Sprintf("/v1/listing/search?lat=%.4f&lon=%.4f&dist_km=%d&limit=20", lat, lon, dist), nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// ... assert response body ...
	mockListingSvc.AssertExpectations(t)
}

func TestRestListingHandler_SearchListings_MissingQuery(t *testing.T) {
	// This test is likely invalid for listings search as query is optional
	// Adjust test logic if a query is mandatory under certain conditions
	t.Skip("Skipping MissingQuery test for listings as query is optional")
}

// TODO: Add tests for GetListingByID invalid ID format
// TODO: Add tests for SearchUserListings (when implemented)
