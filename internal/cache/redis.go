package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ConnectRedis initializes and returns a Redis client instance.
func ConnectRedis(addr, password string, db int) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		// Close the client if ping fails
		_ = rdb.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	fmt.Println("Successfully connected to Redis!")
	return rdb, nil
}

// DisconnectRedis closes the Redis client connection.
func DisconnectRedis(client *redis.Client) error {
	if client == nil {
		return nil
	}
	if err := client.Close(); err != nil {
		return fmt.Errorf("failed to close Redis connection: %w", err)
	}
	fmt.Println("Redis connection closed.")
	return nil
}
