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
	ContextKeyIPAddress ContextKey = "ip-address"
	ContextKeyUserAgent ContextKey = "user-agent"
	ContextKeyDeviceID  ContextKey = "device-id"
	ContextKeyParams    ContextKey = "params"
	ContextKeyHeaders   ContextKey = "headers"
)

func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(ContextKeyUserID).(string); ok {
		return userID
	}

	return ""
}

func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return requestID
	}

	return ""
}

func GetIPAddress(ctx context.Context) string {
	if ipAddress, ok := ctx.Value(ContextKeyIPAddress).(string); ok {
		return ipAddress
	}

	return ""
}

func GetUserAgent(ctx context.Context) string {
	if userAgent, ok := ctx.Value(ContextKeyUserAgent).(string); ok {
		return userAgent
	}

	return ""
}

func GetDeviceID(ctx context.Context) string {
	if deviceID, ok := ctx.Value(ContextKeyDeviceID).(string); ok {
		return deviceID
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
