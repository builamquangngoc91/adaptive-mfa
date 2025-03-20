package cache

import (
	"context"
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

type ICache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration *time.Duration) error
	Del(ctx context.Context, key string) error
	GetAndDel(ctx context.Context, key string) (string, error)
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
	result, err := r.rd.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", Nil
	}
	return result, err
}

func (r *Cache) Set(ctx context.Context, key string, value string, expiration *time.Duration) error {
	return r.rd.Set(ctx, key, value, *expiration).Err()
}

func (r *Cache) Del(ctx context.Context, key string) error {
	return r.rd.Del(ctx, key).Err()
}

func (r *Cache) GetAndDel(ctx context.Context, key string) (string, error) {
	result, err := r.rd.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return "", Nil
	}
	return result, err
}

func (r *Cache) Ping(ctx context.Context) error {
	return r.rd.Ping(ctx).Err()
}

func (r *Cache) Close(ctx context.Context) error {
	return r.rd.Close()
}
