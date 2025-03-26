package sms

import (
	"adaptive-mfa/pkg/logger"
	"adaptive-mfa/pkg/monitor"
	"context"
)

type ISMS interface {
	Ping(ctx context.Context) error
	SendSMS(ctx context.Context, phone string, message string) error
}

type SMS struct{}

func NewSMS() ISMS {
	return &SMS{}
}

func (s *SMS) Ping(ctx context.Context) error {
	return nil
}

func (s *SMS) SendSMS(ctx context.Context, phone string, message string) error {
	logger.NewLogger().
		WithContext(ctx).
		With("phone", phone).
		With("message", message).
		Info("Send sms")
	monitor.SMSSendCounter.WithLabelValues(phone).Inc()
	return nil
}
