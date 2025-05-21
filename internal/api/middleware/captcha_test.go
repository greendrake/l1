package middleware

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
	"greendrake/l1/internal/captcha"
	"greendrake/l1/internal/config"
)

// MockTurnstileVerifier
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

// ... (MockConfigService, setupTestEngine) ...

func setupCaptchaTestEngine(cfg *config.Config, verifier captcha.ITurnstileVerifier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CaptchaMiddleware(cfg, verifier))
	r.GET("/test", func(c *gin.Context) {
		isHuman := c.GetBool(ContextKeyIsHumanVerified)
		c.JSON(http.StatusOK, gin.H{"is_human": isHuman, "xct": c.Writer.Header().Get("X-C-T")})
	})
	return r
}

func TestCaptchaMiddleware_NoHeaders(t *testing.T) {
	cfg := &config.Config{}
	mockVerifier := new(MockTurnstileVerifier)
	router := setupCaptchaTestEngine(cfg, mockVerifier)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["is_human"].(bool)) // Should not be verified
	assert.Empty(t, respBody["xct"])             // No token generated
	mockVerifier.AssertNotCalled(t, "Verify")
	mockVerifier.AssertNotCalled(t, "ValidateHumanToken")
	mockVerifier.AssertNotCalled(t, "GenerateHumanToken")
}

func TestCaptchaMiddleware_ValidXCV(t *testing.T) {
	cfg := &config.Config{CaptchaTokenTTL: 10 * time.Minute}
	mockVerifier := new(MockTurnstileVerifier)
	router := setupCaptchaTestEngine(cfg, mockVerifier)

	challenge := "valid-challenge-token"
	clientIP := "1.1.1.1"
	fingerprint := "fp1"
	spaSess := "sess1"
	expectedHumanToken := "generated-xct-token"

	mockVerifier.On("Verify", mock.Anything, challenge, clientIP).Return(true, nil)
	mockVerifier.On("GenerateHumanToken", "", clientIP, fingerprint, spaSess, cfg.CaptchaTokenTTL).Return(expectedHumanToken, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.Header.Set("X-C-V", challenge)
	req.Header.Set("X-BFP", fingerprint)
	req.Header.Set("X-SPA", spaSess)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.True(t, respBody["is_human"].(bool))          // Should be verified
	assert.Equal(t, expectedHumanToken, respBody["xct"]) // Should generate token
	mockVerifier.AssertExpectations(t)
}

func TestCaptchaMiddleware_InvalidXCV(t *testing.T) {
	cfg := &config.Config{}
	mockVerifier := new(MockTurnstileVerifier)
	router := setupCaptchaTestEngine(cfg, mockVerifier)

	challenge := "invalid-challenge-token"
	clientIP := "2.2.2.2"

	mockVerifier.On("Verify", mock.Anything, challenge, clientIP).Return(false, nil) // Verification fails

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.Header.Set("X-C-V", challenge)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["is_human"].(bool)) // Should not be verified
	assert.Empty(t, respBody["xct"])
	mockVerifier.AssertCalled(t, "Verify", mock.Anything, challenge, clientIP)
	mockVerifier.AssertNotCalled(t, "GenerateHumanToken")
}

func TestCaptchaMiddleware_ValidXCT(t *testing.T) {
	cfg := &config.Config{}
	mockVerifier := new(MockTurnstileVerifier)
	router := setupCaptchaTestEngine(cfg, mockVerifier)

	token := "valid-xct-token"
	clientIP := "3.3.3.3"
	fingerprint := "fp2"
	spaSess := "sess2"

	mockVerifier.On("ValidateHumanToken", token, clientIP, fingerprint, spaSess).Return(true)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.Header.Set("X-C-T", token)
	req.Header.Set("X-BFP", fingerprint)
	req.Header.Set("X-SPA", spaSess)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.True(t, respBody["is_human"].(bool)) // Should be verified
	assert.Empty(t, respBody["xct"])
	mockVerifier.AssertExpectations(t)
	mockVerifier.AssertNotCalled(t, "Verify")
	mockVerifier.AssertNotCalled(t, "GenerateHumanToken")
}

func TestCaptchaMiddleware_InvalidXCT(t *testing.T) {
	cfg := &config.Config{}
	mockVerifier := new(MockTurnstileVerifier)
	router := setupCaptchaTestEngine(cfg, mockVerifier)

	token := "invalid-xct-token"
	clientIP := "4.4.4.4"
	fingerprint := "fp3"
	spaSess := "sess3"

	mockVerifier.On("ValidateHumanToken", token, clientIP, fingerprint, spaSess).Return(false)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	req.Header.Set("X-C-T", token)
	req.Header.Set("X-BFP", fingerprint)
	req.Header.Set("X-SPA", spaSess)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["is_human"].(bool)) // Should not be verified
	assert.Empty(t, respBody["xct"])
	mockVerifier.AssertExpectations(t)
	mockVerifier.AssertNotCalled(t, "Verify")
	mockVerifier.AssertNotCalled(t, "GenerateHumanToken")
}
