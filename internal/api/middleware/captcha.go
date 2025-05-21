package middleware

import (
	"log"
	// "net/http"

	"github.com/gin-gonic/gin"
	"greendrake/l1/internal/captcha"
	"greendrake/l1/internal/config"
)

const (
	// ContextKeyIsHumanVerified holds the key for captcha status in Gin context.
	ContextKeyIsHumanVerified = "isHumanVerified"
)

// CaptchaMiddleware handles Cloudflare Turnstile verification (X-C-V) and token (X-C-T) checks.
func CaptchaMiddleware(cfg *config.Config, verifier captcha.ITurnstileVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		fingerprint := c.GetHeader("X-BFP")
		spaSession := c.GetHeader("X-SPA")
		turnstileToken := c.GetHeader("X-C-T")
		turnstileChallenge := c.GetHeader("X-C-V")

		isHuman := false

		// 1. Check for existing valid X-C-T token
		if turnstileToken != "" {
			if verifier.ValidateHumanToken(turnstileToken, clientIP, fingerprint, spaSession) {
				isHuman = true
				log.Printf("Valid X-C-T token presented for %s|%s|%s", clientIP, fingerprint, spaSession)
			}
		}

		// 2. If no valid X-C-T, check for X-C-V challenge
		if !isHuman && turnstileChallenge != "" {
			log.Printf("Verifying X-C-V challenge for %s|%s|%s", clientIP, fingerprint, spaSession)
			verified, err := verifier.Verify(c.Request.Context(), turnstileChallenge, clientIP)
			if err != nil {
				log.Printf("Error verifying Turnstile token: %v", err)
				// Don't abort, just treat as non-human. Rate limiter will handle it.
			} else if verified {
				isHuman = true
				// Generate a new X-C-T token and add it to the response header
				humanTokenTTL := cfg.CaptchaTokenTTL // Use configured TTL
				// Include UserID in token if user is authenticated? Maybe not needed here.
				newHumanToken, tokenErr := verifier.GenerateHumanToken("", clientIP, fingerprint, spaSession, humanTokenTTL)
				if tokenErr != nil {
					log.Printf("Error generating X-C-T token after successful verification: %v", tokenErr)
				} else {
					c.Header("X-C-T", newHumanToken)
					// Ensure CORS middleware exposes this header (already done)
				}
			}
		}

		// Set the verification status in the context for subsequent middleware/handlers
		c.Set(ContextKeyIsHumanVerified, isHuman)
		c.Next()
	}
}
