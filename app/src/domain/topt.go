package domain

import "errors"

type AddTOTPMethodRequest struct{}

type AddTOTPMethodResponse struct {
	Secret string `json:"secret"`
	Issuer string `json:"issuer"`
}

type VerifyTOTPCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}

func (r VerifyTOTPCodeRequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	if r.Code == "" {
		return errors.New("code is required")
	}

	return nil
}

type VerifyTOTPCodeResponse struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}

type ListMFAMethodsResponse struct {
	Methods []string `json:"methods"`
}

type DeleteTOTPMethodResponse struct{}

type MFAMetadata struct {
	PrivateKey string        `json:"private_key"`
	UserID     string        `json:"user_id"`
	Username   string        `json:"username"`
	Type       UserLoginType `json:"type"`
	Code       string        `json:"code"`
	Attempts   int           `json:"attempts"`
}

type UserLoginType string

const (
	UserLoginTypeMFAMail UserLoginType = "mfa_mail"
	UserLoginTypeMFASMS  UserLoginType = "mfa_sms"
	UserLoginTypeMFATOTP UserLoginType = "mfa_totp"
)
