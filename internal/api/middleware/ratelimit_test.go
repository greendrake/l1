package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"greendrake/l1/internal/api/middleware"
	"greendrake/l1/internal/captcha"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
)

// --- Mocks (Copied from handlers/mocks_test.go as needed) ---

// MockConfigService implements services.IConfigService
type MockConfigService struct {
	mock.Mock
}

func (m *MockConfigService) GetAllPublic(ctx context.Context) (map[string]interface{}, error) { /* ... */
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
func (m *MockConfigService) Get(ctx context.Context, key string) (interface{}, error) { /* ... */
	args := m.Called(ctx, key)
	return args.Get(0), args.Error(1)
}
func (m *MockConfigService) GetInt(ctx context.Context, key string, defaultValue int) int { /* ... */
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.Int(0)
}
func (m *MockConfigService) GetString(ctx context.Context, key string, defaultValue string) string { /* ... */
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.String(0)
}
func (m *MockConfigService) GetBool(ctx context.Context, key string, defaultValue bool) bool { /* ... */
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.Bool(0)
}
func (m *MockConfigService) GetFloat64(ctx context.Context, key string, defaultValue float64) float64 { /* ... */
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	if fVal, ok := args.Get(0).(float64); ok {
		return fVal
	}
	return float64(args.Int(0))
}
func (m *MockConfigService) GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration {
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.Get(0).(time.Duration)
}
func (m *MockConfigService) Load(ctx context.Context) error {
	args := m.Called(ctx)
	_ = args
	return args.Error(0)
}
func (m *MockConfigService) SubscribeToChanges(ctx context.Context) error {
	args := m.Called(ctx)
	_ = args
	return args.Error(0)
}
func (m *MockConfigService) SetConfigValue(ctx context.Context, key string, value interface{}, isPublic bool) error {
	args := m.Called(ctx, key, value, isPublic)
	return args.Error(0)
}
func (m *MockConfigService) GetAPIEndpointConfig(ctx context.Context, apiType models.APIType, endpoint string, isAuthenticated bool) (*models.APIEndpointConfig, error) {
	args := m.Called(ctx, apiType, endpoint, isAuthenticated)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIEndpointConfig), args.Error(1)
}

// MockTurnstileVerifier implements captcha.ITurnstileVerifier
type MockTurnstileVerifier struct {
	mock.Mock
}

func (m *MockTurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	args := m.Called(ctx, token, remoteIP)
	return args.Bool(0), args.Error(1)
}
func (m *MockTurnstileVerifier) GenerateHumanToken(userID, ip, fingerprint, spaSession string, ttl time.Duration) (string, error) {
	args := m.Called(userID, ip, fingerprint, spaSession, ttl)
	return args.String(0), args.Error(1)
}
func (m *MockTurnstileVerifier) ValidateHumanToken(tokenString, ip, fingerprint, spaSession string) bool {
	args := m.Called(tokenString, ip, fingerprint, spaSession)
	return args.Bool(0)
}

func setupTestEngine(cfg *config.Config, configSvc services.IConfigService, verifier captcha.ITurnstileVerifier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	rateLimiter := middleware.NewRateLimiterMiddleware(cfg, configSvc)
	r.Use(middleware.CaptchaMiddleware(cfg, verifier))
	r.Use(rateLimiter.Limit())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	return r
}

func TestRateLimiterMiddleware_HardLimit(t *testing.T) {
	cfg := &config.Config{
		RateLimitHardRefillRate: 1,  // 1 token per second
		RateLimitHardBucketSize: 1,  // Bucket size 1
		RateLimitSoftRefillRate: 10, // High soft limit
		RateLimitSoftBucketSize: 10,
	}
	mockConfigSvc := new(MockConfigService)
	mockVerifier := new(MockTurnstileVerifier) // Add verifier mock
	mockConfigSvc.On("GetAPIEndpointConfig", mock.Anything, models.APITypeREST, "/test", false).Return(nil, nil)
	// No captcha calls expected for hard limit test
	router := setupTestEngine(cfg, mockConfigSvc, mockVerifier) // Pass mocks

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:12345" // Identify client

	// First request should pass
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request immediately should fail (hard limit)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "1.2.3.4:12345"
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	mockConfigSvc.AssertExpectations(t) // Assert the config call was made
}

func TestRateLimiterMiddleware_SoftLimit_CaptchaRequired(t *testing.T) {
	cfg := &config.Config{
		RateLimitHardRefillRate: 10, // High hard limit
		RateLimitHardBucketSize: 10,
		RateLimitSoftRefillRate: 1, // 1 token per second
		RateLimitSoftBucketSize: 1, // Bucket size 1
	}
	mockConfigSvc := new(MockConfigService)
	mockVerifier := new(MockTurnstileVerifier) // Add verifier mock
	mockConfigSvc.On("GetAPIEndpointConfig", mock.Anything, models.APITypeREST, "/test", false).Return(nil, nil)
	// Expect ValidateHumanToken to be called (for X-C-T) and Verify (for X-C-V) - both return false
	mockVerifier.On("ValidateHumanToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false)
	mockVerifier.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return(false, nil) // Assume verify called even if token empty?
	router := setupTestEngine(cfg, mockConfigSvc, mockVerifier)                               // Pass mocks

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "5.6.7.8:12345"

	// First request should pass
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request immediately should hit soft limit (418)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "5.6.7.8:12345"
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTeapot, w2.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w2.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Contains(t, respBody["error"], "Captcha validation required")
	mockConfigSvc.AssertExpectations(t)
}

func TestRateLimiterMiddleware_SoftLimit_BypassWithCaptchaHeader(t *testing.T) {
	cfg := &config.Config{
		RateLimitHardRefillRate: 10,
		RateLimitHardBucketSize: 10,
		RateLimitSoftRefillRate: 1,
		RateLimitSoftBucketSize: 1,
	}
	mockConfigSvc := new(MockConfigService)
	mockVerifier := new(MockTurnstileVerifier) // Add verifier mock
	// Expect config lookups
	mockConfigSvc.On("GetAPIEndpointConfig", mock.Anything, models.APITypeREST, "/test", false).Return(nil, nil)
	// Expect ValidateHumanToken to be called and return true for the second request
	mockVerifier.On("ValidateHumanToken", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(true)
	// Don't expect Verify to be called if X-C-T is valid
	router := setupTestEngine(cfg, mockConfigSvc, mockVerifier) // Pass mocks

	// First request (consumes soft token, calls GetAPIEndpointConfig with false)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "9.1.2.3:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request with captcha header (calls GetAPIEndpointConfig with true)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "9.1.2.3:12345"
	req2.Header.Set("X-C-T", "valid-turnstile-token") // Add header
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	mockConfigSvc.AssertExpectations(t)
}

// TODO: Test cleanupClients logic (harder without time control)
// TODO: Test endpoint-specific limits when implemented
