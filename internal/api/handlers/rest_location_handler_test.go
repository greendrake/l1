package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"greendrake/l1/internal/api/handlers"
	"greendrake/l1/internal/models"
)

// MockLocationService is defined in mocks_test.go

// --- Tests ---

func TestRestLocationHandler_SearchLocations_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockLocationSvc := new(MockLocationService)
	handler := handlers.NewRestLocationHandler(mockLocationSvc)

	r := gin.New()
	r.GET("/v1/location/search", handler.SearchLocations)

	query := "London"
	limit := 10
	expectedDBLocations := []models.Location{
		{ID: 1, Name: "London", CountryCode: "GB", Context: []string{"England", "UK"}, Location: &models.GeoJSON{Type: "Point", Coordinates: []float64{0.1278, 51.5074}}},
		{ID: 2, Name: "London", CountryCode: "CA", Context: []string{"Ontario", "Canada"}, Location: &models.GeoJSON{Type: "Point", Coordinates: []float64{-81.2452, 42.9849}}},
	}
	mockLocationSvc.On("SearchLocations", mock.Anything, query, (*string)(nil), limit).Return(expectedDBLocations, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/location/search?q=London&limit=10", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var respBody []models.LocationAPIResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Len(t, respBody, 2)

	// Assertions for first location
	assert.Equal(t, fmt.Sprintf("%d", expectedDBLocations[0].ID), respBody[0].ID)
	assert.Equal(t, expectedDBLocations[0].Name, respBody[0].Name)
	assert.Equal(t, expectedDBLocations[0].CountryCode, respBody[0].CountryCode)
	assert.Equal(t, "UK, England", respBody[0].Context)
	assert.Equal(t, expectedDBLocations[0].Location.Coordinates, respBody[0].Coordinates)

	// Assertions for second location
	assert.Equal(t, fmt.Sprintf("%d", expectedDBLocations[1].ID), respBody[1].ID)
	assert.Equal(t, expectedDBLocations[1].Name, respBody[1].Name)
	assert.Equal(t, expectedDBLocations[1].CountryCode, respBody[1].CountryCode)
	assert.Equal(t, "Canada, Ontario", respBody[1].Context)
	assert.Equal(t, expectedDBLocations[1].Location.Coordinates, respBody[1].Coordinates)

	mockLocationSvc.AssertExpectations(t)
}

func TestRestLocationHandler_SearchLocations_WithCountry_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockLocationSvc := new(MockLocationService)
	handler := handlers.NewRestLocationHandler(mockLocationSvc)

	r := gin.New()
	r.GET("/v1/location/:country_code/search", handler.SearchLocations)

	query := "Paris"
	limit := 5
	country := "FR"
	expectedDBLocations := []models.Location{
		{ID: 3, Name: "Paris", CountryCode: "FR", Context: []string{"Île-de-France", "France"}, Location: &models.GeoJSON{Type: "Point", Coordinates: []float64{2.3522, 48.8566}}},
	}
	mockLocationSvc.On("SearchLocations", mock.Anything, query, &country, limit).Return(expectedDBLocations, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/location/FR/search?q=Paris&limit=5", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody []models.LocationAPIResponse
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Len(t, respBody, 1)

	assert.Equal(t, fmt.Sprintf("%d", expectedDBLocations[0].ID), respBody[0].ID)
	assert.Equal(t, "Paris", respBody[0].Name)
	assert.Equal(t, "France, Île-de-France", respBody[0].Context)
	assert.Equal(t, expectedDBLocations[0].CountryCode, respBody[0].CountryCode)
	assert.Equal(t, expectedDBLocations[0].Location.Coordinates, respBody[0].Coordinates)

	mockLocationSvc.AssertExpectations(t)
}

// ... (Tests for RestListingHandler)
