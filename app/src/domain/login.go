package domain

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
