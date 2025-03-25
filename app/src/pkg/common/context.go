package common

import (
	"context"
	"net/http"
	"net/url"
)

type ContextKey string

const (
	ContextKeyUserID    ContextKey = "user-id"
	ContextKeyRequestID ContextKey = "request-id"
	ContextKeyParams    ContextKey = "params"
	ContextKeyHeaders   ContextKey = "headers"
)

func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return requestID
	}

	return ""
}

func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(ContextKeyUserID).(string); ok {
		return userID
	}

	return ""
}

func GetParams(ctx context.Context) url.Values {
	if params, ok := ctx.Value(ContextKeyParams).(url.Values); ok {
		return params
	}

	return url.Values{}
}

func GetHeaders(ctx context.Context) http.Header {
	if headers, ok := ctx.Value(ContextKeyHeaders).(http.Header); ok {
		return headers
	}

	return http.Header{}
}
