package sms

import (
	"adaptive-mfa/pkg/monitor"
	"context"
	"fmt"
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
	fmt.Printf("Send sms to %s with message %s\n", phone, message)
	monitor.SMSSendCounter.WithLabelValues(phone).Inc()
	return nil
}
