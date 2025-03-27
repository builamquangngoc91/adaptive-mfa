package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"adaptive-mfa/pkg/cache"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/pkg/ptr"
)

func RateLimit(ctx context.Context, _cache cache.ICache, key string, threshold int64, lockDuration time.Duration, success *bool) error {
	var attempts int64
	attemptsStr, err := _cache.Get(ctx, key)
	if err != nil && !errors.Is(err, cache.Nil) {
		return appError.WithAppError(err, appError.CodeCacheError)
	}

	if attemptsStr != "" {
		attempts, err = strconv.ParseInt(attemptsStr, 10, 64)
		if err != nil {
			attempts = 0
		}
	}

	if attempts >= threshold {
		return appError.ErrorExceededThresholdRateLimit
	}

	switch success {
	case nil:
		// no-op
	case ptr.ToPtr(true):
		if err := _cache.Del(ctx, key); err != nil {
			return appError.WithAppError(err, appError.CodeCacheError)
		}
	case ptr.ToPtr(false):
		if err := _cache.Set(ctx, key, fmt.Sprintf("%d", attempts+1), ptr.ToPtr(lockDuration), false); err != nil {
			return appError.WithAppError(err, appError.CodeCacheError)
		}
	}
	return nil
}
