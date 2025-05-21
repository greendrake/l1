package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestRestUserHandler_GetUserByID_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockUserSvc := new(MockUserService) // Assumes defined in mocks_test.go
	handler := handlers.NewRestUserHandler(mockUserSvc)

	r := gin.New()
	r.GET("/v1/user/:id", handler.GetUserByID)

	userID := utils.NewSixID()
	expectedUser := &models.User{
		ID:        userID,
		Name:      "Test User",
		CreatedAt: time.Now().Add(-24 * time.Hour), // Joined yesterday
	}
	mockUserSvc.On("FindByID", mock.Anything, userID).Return(expectedUser, nil)

	// TODO: Mock listing count and validations when implemented

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/user/"+userID.String(), nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody handlers.PublicUser
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, userID.String(), respBody.ID)
	assert.Equal(t, "Test User", respBody.Name)
	assert.Equal(t, expectedUser.CreatedAt.Format("2006-01-02"), respBody.DateJoined)
	assert.Equal(t, 0, respBody.ListingCount) // Placeholder value
	assert.Empty(t, respBody.Validations)     // Placeholder value
	mockUserSvc.AssertExpectations(t)
}

func TestRestUserHandler_GetUserByID_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockUserSvc := new(MockUserService)
	handler := handlers.NewRestUserHandler(mockUserSvc)

	r := gin.New()
	r.GET("/v1/user/:id", handler.GetUserByID)

	userID := utils.NewSixID()
	mockUserSvc.On("FindByID", mock.Anything, userID).Return(nil, mongo.ErrNoDocuments)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/user/"+userID.String(), nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Contains(t, respBody["error"], "User not found")
	mockUserSvc.AssertExpectations(t)
}

func TestRestUserHandler_GetUserByID_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockUserSvc := new(MockUserService)
	handler := handlers.NewRestUserHandler(mockUserSvc)

	r := gin.New()
	r.GET("/v1/user/:id", handler.GetUserByID)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/user/invalid-id", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Contains(t, respBody["error"], "Invalid user ID format")
	mockUserSvc.AssertNotCalled(t, "FindByID")
}
