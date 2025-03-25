package domain

type AddTOTPMethodRequest struct{}

type AddTOTPMethodResponse struct {
	Secret string `json:"secret"`
	Issuer string `json:"issuer"`
}

type VerifyTOTPCodeRequest struct {
	ReferenceID string `json:"reference_id"`
	Code        string `json:"code"`
}

type VerifyTOTPCodeResponse struct {
	ReferenceID string `json:"reference_id"`
	PrivateKey  string `json:"private_key"`
}

type ListTOTPMethodsRequest struct{}

type ListTOTPMethodsResponse struct {
	Methods []string `json:"methods"`
}

type DeleteTOTPMethodRequest struct{}

type DeleteTOTPMethodResponse struct{}

type MFAMetadata struct {
	PrivateKey string      `json:"private_key"`
	UserID     string      `json:"user_id"`
	Type       UserMFAType `json:"type"`
}

type UserMFAType string

const (
	UserMFATypePhone UserMFAType = "phone"
	UserMFATypeEmail UserMFAType = "email"
	UserMFATypeOTP   UserMFAType = "otp"
)
