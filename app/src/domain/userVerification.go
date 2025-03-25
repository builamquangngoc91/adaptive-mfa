package domain

type SendEmailVerificationRequest struct {
	ReferenceID string `json:"reference_id"`
}

type SendEmailVerificationResponse struct{}

type SendPhoneVerificationRequest struct {
	ReferenceID string `json:"reference_id"`
}

type SendPhoneVerificationResponse struct{}

type VerifyEmailVerificationRequest struct {
	Code string `json:"code"`
}

type VerifyPhoneVerificationRequest struct {
	Code string `json:"code"`
}

type VerifyPhoneVerificationResponse struct{
	
}

type VerifyEmailVerificationResponse struct{}
