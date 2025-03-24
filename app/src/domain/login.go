package domain

type LoginRequest struct {
	Type      LoginType              `json:"type"`
	BasicAuth *BasicAuthLoginRequest `json:"basic_auth"`
	MFA       *MFARequest            `json:"mfa"`
}

type LoginResponse struct {
	Token       string `json:"token"`
	RequiredMFA bool   `json:"required_mfa"`
	ReferenceID string `json:"reference_id"`
}

type BasicAuthLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type MFARequest struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}

type LoginType string

const (
	LoginTypeBasicAuth LoginType = "basic"
	LoginTypeMFALogin  LoginType = "mfa"
)

type SendLoginEmailCodeRequest struct {
	ReferenceID string `json:"reference_id"`
}

type VerifyLoginEmailCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}

type SendLoginPhoneCodeRequest struct {
	ReferenceID string `json:"reference_id"`
}

type VerifyLoginPhoneCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}
