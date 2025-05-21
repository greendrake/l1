package handlers_test

import (
	// "context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	// "time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"greendrake/l1/internal/api/handlers"
	// "greendrake/l1/internal/models"
	// "greendrake/l1/internal/utils"
	// "go.mongodb.org/mongo-driver/mongo"
)

// --- Mocks Removed (Now in mocks_test.go) ---

// --- Tests ---

func TestRestConfigHandler_GetPublicConfig_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockConfigSvc := new(MockConfigService)
	handler := handlers.NewRestConfigHandler(mockConfigSvc)
	r := gin.New()
	r.GET("/v1/config", handler.GetPublicConfig)
	expectedConfig := map[string]interface{}{"APP_NAME": "TestApp", "SOME_PUBLIC_VALUE": true}
	mockConfigSvc.On("GetAllPublic", mock.Anything).Return(expectedConfig, nil)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/config", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig, respBody)
	mockConfigSvc.AssertExpectations(t)
}

func TestRestConfigHandler_GetPublicConfig_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockConfigSvc := new(MockConfigService)
	handler := handlers.NewRestConfigHandler(mockConfigSvc)
	r := gin.New()
	r.GET("/v1/config", handler.GetPublicConfig)
	mockConfigSvc.On("GetAllPublic", mock.Anything).Return(nil, assert.AnError)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/config", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Contains(t, respBody["error"], "Failed to retrieve configuration")
	mockConfigSvc.AssertExpectations(t)
}
