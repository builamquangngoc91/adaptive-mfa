package domain

import "errors"

type SendEmailVerificationRequest struct{}

type SendEmailVerificationResponse struct{}

type SendPhoneVerificationRequest struct{}

type SendPhoneVerificationResponse struct{}

type VerifyEmailVerificationRequest struct {
	Code string `json:"code"`
}

func (r VerifyEmailVerificationRequest) Validate() error {
	if r.Code == "" {
		return errors.New("code is required")
	}

	return nil
}

type VerifyPhoneVerificationRequest struct {
	Code string `json:"code"`
}

func (r VerifyPhoneVerificationRequest) Validate() error {
	if r.Code == "" {
		return errors.New("code is required")
	}

	return nil
}

type VerifyPhoneVerificationResponse struct{}

type VerifyEmailVerificationResponse struct{}
