package services

import (
	"context"
	// "errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9" // Added
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	// "github.com/redis/go-redis/v9" // TODO: Add Redis for caching/pubsub
)

// IConfigService defines the interface for accessing configuration.
type IConfigService interface {
	GetAllPublic(ctx context.Context) (map[string]interface{}, error)
	Get(ctx context.Context, key string) (interface{}, error)
	GetInt(ctx context.Context, key string, defaultValue int) int
	GetString(ctx context.Context, key string, defaultValue string) string
	GetBool(ctx context.Context, key string, defaultValue bool) bool
	GetFloat64(ctx context.Context, key string, defaultValue float64) float64
	GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration
	// Set(ctx context.Context, key string, value interface{}, isPublic bool) error
	// LoadAndCache(ctx context.Context) error // Renamed Load
	Load(ctx context.Context) error                                                                                                             // Added
	SubscribeToChanges(ctx context.Context) error                                                                                               // Added
	SetConfigValue(ctx context.Context, key string, value interface{}, isPublic bool) error                                                     // Added
	GetAPIEndpointConfig(ctx context.Context, apiType models.APIType, endpoint string, isAuthenticated bool) (*models.APIEndpointConfig, error) // Added
	// SubscribeToChanges() error // TODO
}

const (
	configCollection    = "configuration"
	apiConfigCollection = "api_endpoints_config" // Added
	configUpdateChannel = "config_updates"
)

// configService implements IConfigService.
type configService struct {
	db       *mongo.Database
	cfg      *config.Config                       // Holds initial defaults loaded from .env
	rdb      *redis.Client                        // Added Redis client
	cache    map[string]interface{}               // Simple in-memory cache for now
	apiCache map[string]*models.APIEndpointConfig // Added cache for API configs
	mutex    sync.RWMutex                         // Mutex for thread-safe cache access
}

// NewConfigService creates a new ConfigService.
func NewConfigService(db *mongo.Database, initialCfg *config.Config, rdb *redis.Client) IConfigService {
	s := &configService{
		db:       db,
		cfg:      initialCfg,
		rdb:      rdb, // Added
		cache:    make(map[string]interface{}),
		apiCache: make(map[string]*models.APIEndpointConfig), // Initialize API cache
	}
	// Load initial config from DB during startup
	if err := s.Load(context.Background()); err != nil {
		// Log error but continue? Or Fatal? Depends on requirements.
		log.Printf("WARNING: Failed to load initial config from DB: %v. Using defaults from .env", err)
	}
	// Start background listener for updates
	go func() {
		if err := s.SubscribeToChanges(context.Background()); err != nil {
			log.Printf("CRITICAL: Config Pub/Sub listener stopped: %v", err)
			// Consider more robust error handling/restart logic here
		}
	}()
	return s
}

// ConfigEntry represents a document in the configuration collection.
type ConfigEntry struct {
	Key    string      `bson:"key"`
	Value  interface{} `bson:"value"`
	Public bool        `bson:"public"`
}

// Load fetches all config entries from DB and populates the in-memory cache.
// Now also loads API endpoint configs.
func (s *configService) Load(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	collection := s.db.Collection(configCollection)
	cursor, err := collection.Find(ctx, bson.M{}) // Find all entries
	if err != nil {
		return fmt.Errorf("failed to query config collection: %w", err)
	}
	defer cursor.Close(ctx)

	newCache := make(map[string]interface{})
	for cursor.Next(ctx) {
		var entry ConfigEntry
		if err := cursor.Decode(&entry); err == nil {
			newCache[entry.Key] = entry.Value
		} else {
			log.Printf("Warning: Failed to decode config entry during load: %v", err)
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("error iterating config cursor: %w", err)
	}

	s.cache = newCache
	log.Printf("Loaded %d entries into config cache from DB.", len(s.cache))

	// Load API endpoint config
	apiCollection := s.db.Collection(apiConfigCollection)
	apiCursor, err := apiCollection.Find(ctx, bson.M{}) // Load all API configs
	if err != nil {
		// Log error but maybe don't fail the whole load?
		log.Printf("Error querying API endpoint configs: %v", err)
	} else {
		defer apiCursor.Close(ctx)
		newAPICache := make(map[string]*models.APIEndpointConfig)
		for apiCursor.Next(ctx) {
			var entry models.APIEndpointConfig
			if err := apiCursor.Decode(&entry); err == nil {
				// Key by Type + Endpoint + AuthRequired status
				cacheKey := fmt.Sprintf("%s#%s#%t", entry.Type, entry.Endpoint, entry.AuthRequired)
				newAPICache[cacheKey] = &entry
			} else {
				log.Printf("Warning: Failed to decode API config entry during load: %v", err)
			}
		}
		if err := apiCursor.Err(); err != nil {
			log.Printf("Error iterating API config cursor: %v", err)
		}
		s.apiCache = newAPICache
		log.Printf("Loaded %d API endpoint configs into cache from DB.", len(s.apiCache))
	}

	log.Printf("Loaded %d general config entries and %d API configs into cache from DB.", len(s.cache), len(s.apiCache))
	return nil // Return nil even if API config load had issues, maybe?
}

// GetAllPublic retrieves all configuration parameters marked as public from DB.
func (s *configService) GetAllPublic(ctx context.Context) (map[string]interface{}, error) {
	// This method directly queries the DB for public keys, doesn't use the cache directly
	// as the cache might contain non-public keys.
	publicConfig := map[string]interface{}{}
	collection := s.db.Collection(configCollection)
	filter := bson.M{"public": true}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query public config from DB: %w", err)
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var entry ConfigEntry
		if err := cursor.Decode(&entry); err == nil {
			publicConfig[entry.Key] = entry.Value
		} else {
			fmt.Printf("Warning: Failed to decode public config entry: %v\n", err)
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("error iterating public config cursor: %w", err)
	}

	// Include APP_NAME from initial config if not overridden in DB?
	if _, exists := publicConfig["APP_NAME"]; !exists {
		publicConfig["APP_NAME"] = s.cfg.AppName
	}

	return publicConfig, nil
}

// Get retrieves a specific configuration value, checking cache first, then defaults.
// Note: This implementation currently doesn't hit the DB after initial load.
// A full implementation would fetch from DB on cache miss or use Pub/Sub for updates.
func (s *configService) Get(ctx context.Context, key string) (interface{}, error) {
	s.mutex.RLock()
	val, exists := s.cache[key]
	s.mutex.RUnlock()

	if exists {
		return val, nil
	}

	// TODO: Implement fetching from DB on cache miss?
	// For now, fall back to initial .env defaults if key known
	switch key {
	case "APP_NAME":
		return s.cfg.AppName, nil
	case "MONGO_URI":
		return s.cfg.MongoURI, nil // Example non-public
	// Add other known keys from initial config as fallbacks
	// Be careful not to expose sensitive defaults here.
	default:
		// Key not found in cache or known defaults
		return nil, fmt.Errorf("config key '%s' not found", key)
	}
}

// Helper methods for type-safe access with defaults
func (s *configService) GetString(ctx context.Context, key string, defaultValue string) string {
	val, err := s.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	if strVal, ok := val.(string); ok {
		return strVal
	}
	log.Printf("Warning: Config key '%s' is not a string, using default.", key)
	return defaultValue
}

func (s *configService) GetInt(ctx context.Context, key string, defaultValue int) int {
	val, err := s.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	// MongoDB might store numbers as float64 or int32/64
	switch v := val.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v) // Be careful with potential truncation
	default:
		log.Printf("Warning: Config key '%s' is not an integer type (%T), using default.", key, val)
		return defaultValue
	}
}

func (s *configService) GetBool(ctx context.Context, key string, defaultValue bool) bool {
	val, err := s.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	if boolVal, ok := val.(bool); ok {
		return boolVal
	}
	log.Printf("Warning: Config key '%s' is not a boolean, using default.", key)
	return defaultValue
}

// GetFloat64 retrieves a config value as float64, with fallback and type conversion.
func (s *configService) GetFloat64(ctx context.Context, key string, defaultValue float64) float64 {
	val, err := s.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	default:
		log.Printf("Warning: Config key '%s' is not a float64 type (%T), using default.", key, val)
		return defaultValue
	}
}

// GetDuration retrieves a config value as time.Duration (assuming value is stored as seconds).
func (s *configService) GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration {
	val, err := s.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	// Assuming duration stored as integer seconds in DB/cache
	switch v := val.(type) {
	case int:
		return time.Duration(v) * time.Second
	case int32:
		return time.Duration(v) * time.Second
	case int64:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v) * time.Second // Handle potential floats
	default:
		log.Printf("Warning: Config key '%s' is not a numeric type for duration (%T), using default.", key, val)
		return defaultValue
	}
}

// SubscribeToChanges listens for update messages on Redis Pub/Sub.
func (s *configService) SubscribeToChanges(ctx context.Context) error {
	if s.rdb == nil {
		log.Println("Redis client not configured, cannot subscribe to config changes.")
		return nil // Not an error if Redis isn't configured
	}

	pubsub := s.rdb.Subscribe(ctx, configUpdateChannel)
	defer pubsub.Close()

	// Wait for confirmation that subscription is created before publishing anything.
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive confirmation from Redis Pub/Sub subscription: %w", err)
	}

	// Go channel which receives messages.
	ch := pubsub.Channel()
	log.Println("Subscribed to Redis channel for config updates:", configUpdateChannel)

	for msg := range ch {
		log.Printf("Received config update notification on channel %s: %s", msg.Channel, msg.Payload)
		// Payload could contain specific keys updated, or just be a general signal
		// For simplicity, reload all config on any notification
		if err := s.Load(context.Background()); err != nil {
			log.Printf("ERROR reloading config from DB after notification: %v", err)
			// Continue listening despite error?
		}
	}

	log.Println("Config Pub/Sub listener stopped.")
	return nil // Or return context error if ctx was cancelled
}

// SetConfigValue updates or inserts a config value in the DB and publishes an update.
func (s *configService) SetConfigValue(ctx context.Context, key string, value interface{}, isPublic bool) error {
	collection := s.db.Collection(configCollection)
	filter := bson.M{"key": key}
	update := bson.M{
		"$set": bson.M{
			"key":    key,
			"value":  value,
			"public": isPublic,
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to upsert config key '%s' in DB: %w", key, err)
	}

	// Publish notification to Redis
	if s.rdb != nil {
		if err := s.rdb.Publish(ctx, configUpdateChannel, key).Err(); err != nil {
			// Log error but don't fail the operation?
			log.Printf("Warning: Failed to publish config update notification for key '%s': %v", key, err)
		}
	}

	// Optionally, update local cache immediately?
	// s.mutex.Lock()
	// s.cache[key] = value
	// s.mutex.Unlock()
	// Or rely on the pub/sub message triggering a reload via s.Load()

	log.Printf("Updated config key '%s' and published notification.", key)
	return nil
}

// GetAPIEndpointConfig retrieves the specific config for an API endpoint/method.
func (s *configService) GetAPIEndpointConfig(ctx context.Context, apiType models.APIType, endpoint string, isAuthenticated bool) (*models.APIEndpointConfig, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s#%s#%t", apiType, endpoint, isAuthenticated)
	s.mutex.RLock()
	config, exists := s.apiCache[cacheKey]
	s.mutex.RUnlock()

	if exists {
		return config, nil
	}

	// Fallback: Check for a guest config if the authenticated one wasn't found
	if isAuthenticated {
		cacheKeyGuest := fmt.Sprintf("%s#%s#%t", apiType, endpoint, false)
		s.mutex.RLock()
		configGuest, existsGuest := s.apiCache[cacheKeyGuest]
		s.mutex.RUnlock()
		if existsGuest {
			return configGuest, nil
		}
	}

	// Not found in cache (potentially hasn't been loaded from DB or doesn't exist)
	// We don't query DB on miss here; rely on initial load and Pub/Sub updates.
	// Return nil, indicating defaults should be used.
	return nil, nil
}
