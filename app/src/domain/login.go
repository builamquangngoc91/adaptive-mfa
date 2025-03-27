package domain

import "errors"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (r LoginRequest) Validate() error {
	if r.Username == "" {
		return errors.New("username is required")
	}

	if r.Password == "" {
		return errors.New("password is required")
	}

	return nil
}

type LoginResponse struct {
	Token       string `json:"token,omitempty"`
	RequiredMFA bool   `json:"required_mfa"`
	ReferenceID string `json:"reference_id,omitempty"`
}

type LoginWithMFARequest struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}

func (r LoginWithMFARequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	if r.PrivateKey == "" {
		return errors.New("private key is required")
	}

	return nil
}

type LoginWithMFAResponse struct {
	Token string `json:"token"`
}

type LoginType string

const (
	LoginTypeBasicAuth LoginType = "basic"
	LoginTypeMFALogin  LoginType = "mfa"
)

type SendLoginEmailCodeRequest struct {
	ReferenceID string `json:"reference_id"`
}

func (r SendLoginEmailCodeRequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	return nil
}

type SendLoginEmailCodeResponse struct {
	Code       string `json:"code,omitempty"`
	DisavowURL string `json:"disavow_url,omitempty"`
}

type VerifyLoginEmailCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}

func (r VerifyLoginEmailCodeRequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	if r.Code == "" {
		return errors.New("code is required")
	}

	return nil
}

type VerifyLoginEmailCodeResponse struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}

type SendLoginPhoneCodeRequest struct {
	ReferenceID string `json:"reference_id"`
}

func (r SendLoginPhoneCodeRequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	return nil
}

type SendLoginPhoneCodeResponse struct {
	Code       string `json:"code,omitempty"`
	DisavowURL string `json:"disavow_url,omitempty"`
}

type VerifyLoginPhoneCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}

func (r VerifyLoginPhoneCodeRequest) Validate() error {
	if r.ReferenceID == "" {
		return errors.New("reference ID is required")
	}

	if r.Code == "" {
		return errors.New("code is required")
	}

	return nil
}

type VerifyLoginPhoneCodeResponse struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}
