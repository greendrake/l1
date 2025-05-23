package models

// APIType defines whether an endpoint is REST or JSON API.
type APIType string

const (
	APITypeREST APIType = "REST"
	APITypeJSON APIType = "JSON"
)

// RateLimitConfig holds token bucket parameters.
type RateLimitConfig struct {
	BucketSize      int `bson:"bucket_size" json:"bucket_size"`
	TokenRefillRate int `bson:"token_refill_rate" json:"token_refill_rate"` // Tokens per second
}

// APIEndpointConfig defines configuration for a specific API endpoint or method.
// Stored in the `api_endpoints_config` collection.
type APIEndpointConfig struct {
	Base          `bson:",inline"`
	Type          APIType          `bson:"type" json:"type"`         // REST or JSON
	Endpoint      string           `bson:"endpoint" json:"endpoint"` // Path for REST, method name for JSON
	AuthRequired  bool             `bson:"auth_required" json:"auth_required"`
	RateLimitSoft *RateLimitConfig `bson:"rate_limit_soft,omitempty" json:"rate_limit_soft,omitempty"`
	RateLimitHard *RateLimitConfig `bson:"rate_limit_hard,omitempty" json:"rate_limit_hard,omitempty"`
	// Deleted     bool               `bson:"deleted" json:"-"`
}
