package domain

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

type ListTOTPMethodsResponse struct {
	Methods []string `json:"methods"`
}

type MFAMetadata struct {
	PrivateKey string `json:"private_key"`
	UserID     string `json:"user_id"`
}
