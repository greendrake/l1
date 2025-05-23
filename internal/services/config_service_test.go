package services

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/utils"
)

func setupTestDBConfig(t *testing.T, dbName string) *mongo.Database {
	return utils.SetupTestDB(t, dbName, "config")
}

func setupRedis(t *testing.T) *redis.Client {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx := context.Background()
	err := rdb.FlushAll(ctx).Err()
	require.NoError(t, err, "Failed to flush Redis")
	return rdb
}

func TestConfigService_CRUD(t *testing.T) {
	db := setupTestDBConfig(t, "testdb_config_service_crud")
	cfg := &config.Config{AppName: "TestApp"}
	rdb := setupRedis(t)
	svc := NewConfigService(db, cfg, rdb)
	ctx := context.Background()

	// Wait for initial load
	time.Sleep(100 * time.Millisecond)

	// Set and get string
	err := svc.SetConfigValue(ctx, "test_key", "test_value", true)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	val, err := svc.Get(ctx, "test_key")
	assert.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Get non-existent key
	_, err = svc.Get(ctx, "does_not_exist")
	assert.Error(t, err)

	// Set and get int
	err = svc.SetConfigValue(ctx, "int_key", 42, true)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	i := svc.GetInt(ctx, "int_key", 0)
	assert.Equal(t, 42, i)

	// Set and get bool
	err = svc.SetConfigValue(ctx, "bool_key", true, true)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	b := svc.GetBool(ctx, "bool_key", false)
	assert.True(t, b)

	// Set and get duration (as seconds)
	err = svc.SetConfigValue(ctx, "duration_key", int64(60), true) // Use int64 for duration
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	dur := svc.GetDuration(ctx, "duration_key", 0*time.Second)
	assert.Equal(t, 60*time.Second, dur)

	// Delete key by setting it to nil
	err = svc.SetConfigValue(ctx, "test_key", nil, true)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	// Verify key is deleted from both MongoDB and Redis
	_, err = db.Collection("config").FindOne(ctx, map[string]string{"key": "test_key"}).DecodeBytes()
	assert.Error(t, err)
	_, err = rdb.Get(ctx, "config:test_key").Result()
	assert.Error(t, err)
}

func TestConfigService_Basic(t *testing.T) {
	db := setupTestDBConfig(t, "testdb_config_service_basic")
	cfg := &config.Config{AppName: "TestApp"}
	rdb := setupRedis(t)
	svc := NewConfigService(db, cfg, rdb)
	ctx := context.Background()

	// Wait for initial load
	time.Sleep(100 * time.Millisecond)

	// Set and get config value
	err := svc.SetConfigValue(ctx, "foo", "bar", true)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // Wait for cache sync

	val, err := svc.Get(ctx, "foo")
	assert.NoError(t, err)
	assert.Equal(t, "bar", val)

	// Get public config
	pub, err := svc.GetAllPublic(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "bar", pub["foo"])

	// Type helpers
	assert.Equal(t, "bar", svc.GetString(ctx, "foo", "baz"))
	assert.Equal(t, 42, svc.GetInt(ctx, "notfound", 42))
	assert.Equal(t, false, svc.GetBool(ctx, "notfound", false))
	assert.Equal(t, 3.14, svc.GetFloat64(ctx, "notfound", 3.14))
	assert.Equal(t, 5*time.Second, svc.GetDuration(ctx, "notfound", 5*time.Second))
}
