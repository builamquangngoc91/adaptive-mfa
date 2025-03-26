package logger

import (
	"adaptive-mfa/pkg/common"
	"context"
	"log/slog"
	"os"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
}

type ILogger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	WithContext(ctx context.Context) ILogger
	With(key string, args ...any) ILogger
}

type logger struct {
	ctx      context.Context
	metadata map[string]interface{}
}

func NewLogger() ILogger {
	return &logger{
		ctx:      context.Background(),
		metadata: make(map[string]any),
	}
}

func (l *logger) WithContext(ctx context.Context) ILogger {
	l.ctx = ctx
	return l
}

func (l *logger) With(key string, args ...any) ILogger {
	l.metadata[key] = args
	return l
}

func (l *logger) parseDataFromContext() {
	if userID := common.GetUserID(l.ctx); userID != "" {
		l.metadata["user_id"] = userID
	}
	if requestID := common.GetRequestID(l.ctx); requestID != "" {
		l.metadata["request_id"] = requestID
	}
}

func (l *logger) Info(msg string, args ...any) {
	l.parseDataFromContext()
	slog.With(slog.Any("metadata", l.metadata)).Info(msg, args...)
}

func (l *logger) Error(msg string, args ...any) {
	l.parseDataFromContext()
	slog.With(slog.Any("metadata", l.metadata)).Error(msg, args...)
}

func (l *logger) Debug(msg string, args ...any) {
	l.parseDataFromContext()
	slog.With(slog.Any("metadata", l.metadata)).Debug(msg, args...)
}

func (l *logger) Warn(msg string, args ...any) {
	l.parseDataFromContext()
	slog.With(slog.Any("metadata", l.metadata)).Warn(msg, args...)
}
