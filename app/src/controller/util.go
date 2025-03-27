package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"adaptive-mfa/pkg/cache"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/pkg/monitor"
	"adaptive-mfa/pkg/ptr"
)

func RateLimit(ctx context.Context, _cache cache.ICache, key string, threshold int64, lockDuration time.Duration, fn func() (bool, error)) error {
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

	success, err := fn()
	if err != nil {
		return err
	}
	fmt.Println("success", success)

	if success {
		fmt.Println("success1", success)
		if err := _cache.Del(ctx, key); err != nil {
			fmt.Println("err", err)
			return appError.WithAppError(err, appError.CodeCacheError)
		}
		return nil
	}
	if err := _cache.Set(ctx, key, fmt.Sprintf("%d", attempts+1), ptr.ToPtr(lockDuration), false); err != nil {
		return appError.WithAppError(err, appError.CodeCacheError)
	}
	return nil
}

func IncrementLoginFailedCounter(ctx context.Context, userID string, ipAddress string) {
	monitor.LoginFailedWithIPCounter.WithLabelValues(userID, ipAddress).Inc()
	monitor.LoginFailedCounter.WithLabelValues(userID).Inc()
}
