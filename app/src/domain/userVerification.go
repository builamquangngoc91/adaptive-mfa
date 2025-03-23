package domain

type VerifyEmailVerificationRequest struct {
	Code string `json:"code"`
}

type VerifyPhoneVerificationRequest struct {
	Code string `json:"code"`
}
