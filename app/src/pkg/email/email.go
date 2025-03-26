package email

import (
	"adaptive-mfa/pkg/logger"
	"adaptive-mfa/pkg/monitor"
	"context"
	"fmt"
)

type IEmail interface {
	Ping(ctx context.Context) error
	SendEmail(ctx context.Context, email string, subject string, body string) error
}

type Email struct{}

func NewEmail() IEmail {
	return &Email{}
}

func (e *Email) SendEmail(ctx context.Context, email string, subject string, body string) error {
	logger.NewLogger().
		WithContext(ctx).
		With("email", email).
		With("subject", subject).
		With("body", body).
		Info("Send email")
	monitor.EmailSendCounter.WithLabelValues(email).Inc()
	return nil
}

func (e *Email) Ping(ctx context.Context) error {
	fmt.Println("Ping")
	return nil
}
