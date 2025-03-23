package common

type ContextKey string

const (
	ContextKeyUserID    ContextKey = "user-id"
	ContextKeyRequestID ContextKey = "request-id"
)
