package cache

import "fmt"

const (
	TokenKeyPrefix                 = "token"
	EmailVerificationCodeKeyPrefix = "email_verification_code"
	PhoneVerificationCodeKeyPrefix = "phone_verification_code"
	MFAReferenceIDKeyPrefix        = "mfa_reference_id"
)

func GetTokenKey(token string) string {
	return fmt.Sprintf("%s:%s", TokenKeyPrefix, token)
}

func GetEmailVerificationCodeKey(userID string) string {
	return fmt.Sprintf("%s:%s", EmailVerificationCodeKeyPrefix, userID)
}

func GetPhoneVerificationCodeKey(userID string) string {
	return fmt.Sprintf("%s:%s", PhoneVerificationCodeKeyPrefix, userID)
}

func GetMFAReferenceIDKey(referenceID string) string {
	return fmt.Sprintf("%s:%s", MFAReferenceIDKeyPrefix, referenceID)
}
