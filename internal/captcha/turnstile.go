package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5" // Use standard JWT package
	"greendrake/l1/internal/config"
)

// ITurnstileVerifier defines the interface for verifying Cloudflare Turnstile tokens.
type ITurnstileVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
	GenerateHumanToken(userID, ip, fingerprint, spaSession string, ttl time.Duration) (string, error)
	ValidateHumanToken(tokenString, ip, fingerprint, spaSession string) bool
}

// CloudflareResponse is the expected structure from the siteverify endpoint.
type CloudflareResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"` // Timestamp of challenge load
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// turnstileVerifier implements ITurnstileVerifier.
type turnstileVerifier struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewTurnstileVerifier creates a new Turnstile verifier.
func NewTurnstileVerifier(cfg *config.Config) ITurnstileVerifier {
	return &turnstileVerifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 5 * time.Second}, // Add timeout
	}
}

// Verify calls the Cloudflare siteverify endpoint.
func (v *turnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if v.cfg.CloudflareTurnstileSecretKey == "" {
		log.Println("WARN: Cloudflare Turnstile secret key not configured. Skipping verification.")
		// Return true in dev/testing if no key? Or specific error?
		return true, nil // Assume success if not configured for easier dev
	}

	formData := map[string]string{
		"secret":   v.cfg.CloudflareTurnstileSecretKey,
		"response": token,
	}
	if remoteIP != "" {
		formData["remoteip"] = remoteIP
	}

	jsonData, _ := json.Marshal(formData)
	req, err := http.NewRequestWithContext(ctx, "POST", v.cfg.CloudflareSiteVerifyURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating Turnstile request: %v", err)
		return false, fmt.Errorf("failed to create turnstile request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		log.Printf("Error calling Turnstile siteverify: %v", err)
		return false, fmt.Errorf("failed to contact turnstile service")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Turnstile response body: %v", err)
		return false, fmt.Errorf("failed to read turnstile response")
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Turnstile siteverify returned non-OK status: %d - Body: %s", resp.StatusCode, string(body))
		return false, fmt.Errorf("turnstile verification failed with status %d", resp.StatusCode)
	}

	var cfResp CloudflareResponse
	if err := json.Unmarshal(body, &cfResp); err != nil {
		log.Printf("Error unmarshalling Turnstile response body: %v - Body: %s", err, string(body))
		return false, fmt.Errorf("failed to parse turnstile response")
	}

	if !cfResp.Success {
		log.Printf("Turnstile verification unsuccessful. Error codes: %v", cfResp.ErrorCodes)
	}

	return cfResp.Success, nil
}

// HumanTokenClaims defines the structure for the X-C-T token.
type HumanTokenClaims struct {
	UserID               string `json:"uid,omitempty"` // Optional: Link to user if logged in?
	IP                   string `json:"ip"`
	Fingerprint          string `json:"bfp"`
	SPASession           string `json:"spa"`
	jwt.RegisteredClaims        // Use imported jwt package type
}

// GenerateHumanToken creates a signed token confirming successful captcha validation.
func (v *turnstileVerifier) GenerateHumanToken(userID, ip, fingerprint, spaSession string, ttl time.Duration) (string, error) {
	expirationTime := time.Now().Add(ttl)
	claims := &HumanTokenClaims{
		UserID:      userID, // Can be empty if guest
		IP:          ip,
		Fingerprint: fingerprint,
		SPASession:  spaSession,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "l1-captcha", // Example issuer
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(v.cfg.JwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign human token: %w", err)
	}
	return tokenString, nil
}

// ValidateHumanToken validates the X-C-T token against current request details.
func (v *turnstileVerifier) ValidateHumanToken(tokenString, ip, fingerprint, spaSession string) bool {
	claims := &HumanTokenClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.cfg.JwtSecret), nil
	})

	if err != nil || !token.Valid {
		log.Printf("Invalid X-C-T token: %v", err)
		return false
	}

	// Check if IP, Fingerprint, and SPA Session match the current request
	if claims.IP != ip || claims.Fingerprint != fingerprint || claims.SPASession != spaSession {
		log.Printf("X-C-T token mismatch: IP(%s vs %s) BFP(%s vs %s) SPA(%s vs %s)",
			claims.IP, ip, claims.Fingerprint, fingerprint, claims.SPASession, spaSession)
		return false
	}

	// Expiry is checked by token.Valid
	return true
}
