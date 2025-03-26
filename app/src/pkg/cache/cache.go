package cache

import (
	"adaptive-mfa/pkg/logger"
	"adaptive-mfa/pkg/ptr"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var _ ICache = &Cache{}

var Nil = errors.New("nil")

type CacheConfig struct {
	Host string
	Port string
	DB   int
}

//go:generate mockgen -source=cache.go -destination=./mock/cache.go -package=mock
type ICache interface {
	Get(ctx context.Context, key string) (string, error)
	GetJSON(ctx context.Context, key string, value interface{}) error
	Set(ctx context.Context, key string, value string, expiration *time.Duration, keepTTL bool) error
	SetJSON(ctx context.Context, key string, value interface{}, expiration *time.Duration, keepTTL bool) error
	Del(ctx context.Context, key string) error
	GetAndDel(ctx context.Context, key string) (string, error)
	GetAndDelJSON(ctx context.Context, key string, value interface{}) error
	Ping(ctx context.Context) error
	Close(ctx context.Context) error
}

type Cache struct {
	rd *redis.Client
}

func New(cfg *CacheConfig) (ICache, error) {
	rd := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		DB:   cfg.DB,
	})
	return &Cache{rd: rd}, nil
}

func (r *Cache) Get(ctx context.Context, key string) (string, error) {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		Info("Getting value from cache")
	result, err := r.rd.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", Nil
		}
		return "", err
	}
	return result, nil
}

func (r *Cache) GetJSON(ctx context.Context, key string, value interface{}) error {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		With("value", value).
		Info("Getting value from cache")
	result, err := r.rd.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Nil
		}
		return err
	}
	return json.Unmarshal([]byte(result), value)
}

func (r *Cache) Set(ctx context.Context, key string, value string, expiration *time.Duration, keepTTL bool) error {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		With("value", value).
		With("expiration", expiration).
		Info("Setting value in cache")
	if keepTTL {
		expiration = ptr.ToPtr(time.Duration(redis.KeepTTL))
	}
	return r.rd.Set(ctx, key, value, *expiration).Err()
}

func (r *Cache) SetJSON(ctx context.Context, key string, value interface{}, expiration *time.Duration, keepTTL bool) error {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		With("value", value).
		With("expiration", expiration).
		Info("Setting value in cache")
	json, err := json.Marshal(value)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Nil
		}
		return err
	}
	if keepTTL {
		expiration = ptr.ToPtr(time.Duration(redis.KeepTTL))
	}
	return r.rd.Set(ctx, key, json, *expiration).Err()
}

func (r *Cache) Del(ctx context.Context, key string) error {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		Info("Deleting value from cache")
	return r.rd.Del(ctx, key).Err()
}

func (r *Cache) GetAndDel(ctx context.Context, key string) (string, error) {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		Info("Getting and deleting value from cache")
	result, err := r.rd.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", Nil
		}
		return "", err
	}
	return result, nil
}

func (r *Cache) GetAndDelJSON(ctx context.Context, key string, value interface{}) error {
	logger.NewLogger().
		WithContext(ctx).
		With("key", key).
		Info("Getting and deleting value from cache")
	result, err := r.rd.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Nil
		}
		return err
	}
	return json.Unmarshal([]byte(result), value)
}

func (r *Cache) Ping(ctx context.Context) error {
	return r.rd.Ping(ctx).Err()
}

func (r *Cache) Close(ctx context.Context) error {
	return r.rd.Close()
}
