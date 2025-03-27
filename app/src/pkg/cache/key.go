package cache

import "fmt"

const (
	TokenKeyPrefix                     = "token"
	EmailVerificationCodeKeyPrefix     = "email_verification_code"
	PhoneVerificationCodeKeyPrefix     = "phone_verification_code"
	MFAReferenceIDKeyPrefix            = "mfa_reference_id"
	LoginAttemptsKeyPrefix             = "login_attempts"
	VerifyLoginEmailCodeKeyPrefix      = "verify_login_email_code"
	VerifyLoginPhoneCodeKeyPrefix      = "verify_login_phone_code"
	LoginVerificationAttemptsKeyPrefix = "login_verification_attempts"
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

func GetLoginAttemptsKey(userID, ipAddress string) string {
	return fmt.Sprintf("%s:%s:%s", LoginAttemptsKeyPrefix, userID, ipAddress)
}

func GetLoginVerificationAttemptsKey(userID, ipAddress string) string {
	return fmt.Sprintf("%s:%s:%s", LoginVerificationAttemptsKeyPrefix, userID, ipAddress)
}
