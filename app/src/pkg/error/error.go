package error

import (
	"errors"
	"net/http"
)

type Code int

const (
	CodeUsernameOrPasswordInvalid Code = 104000001
	CodeInvalidMFAReferenceID     Code = 104000002
	CodeInvalidMFAPrivateKey      Code = 104000003
	CodeInvalidMFACode            Code = 104000004
	CodeBadRequest                Code = 104000005
	CodeExceededMFACodeAttempts   Code = 104000006
	CodeMFAForPhoneNotFound       Code = 104000007
	CodeMFAForEmailNotFound       Code = 104000008
	CodeUnauthorized              Code = 104010000
	CodeInternalServerError       Code = 105000001
	CodeCacheError                Code = 105000002
	CodeSendSMSFailed             Code = 105000003
	CodeSendEmailFailed           Code = 105000004
	CodeTOTPMethodAlreadyExists   Code = 104000009
)

type responseInfo struct {
	Message    string
	StatusCode int
}

var mapCodeToMessage = map[Code]responseInfo{
	CodeUsernameOrPasswordInvalid: {
		Message:    "username or password invalid",
		StatusCode: http.StatusBadRequest,
	},
	CodeInvalidMFAReferenceID: {
		Message:    "invalid mfa reference id",
		StatusCode: http.StatusBadRequest,
	},
	CodeInvalidMFAPrivateKey: {
		Message:    "invalid mfa private key",
		StatusCode: http.StatusBadRequest,
	},
	CodeInvalidMFACode: {
		Message:    "invalid mfa code",
		StatusCode: http.StatusBadRequest,
	},
	CodeBadRequest: {
		Message:    "bad request",
		StatusCode: http.StatusBadRequest,
	},
	CodeExceededMFACodeAttempts: {
		Message:    "exceeded mfa code attempts",
		StatusCode: http.StatusTooManyRequests,
	},
	CodeMFAForPhoneNotFound: {
		Message:    "mfa for phone not found",
		StatusCode: http.StatusBadRequest,
	},
	CodeMFAForEmailNotFound: {
		Message:    "mfa for email not found",
		StatusCode: http.StatusBadRequest,
	},
	CodeSendEmailFailed: {
		Message:    "send email failed",
		StatusCode: http.StatusInternalServerError,
	},
	CodeTOTPMethodAlreadyExists: {
		Message:    "totp method already exists",
		StatusCode: http.StatusBadRequest,
	},
	CodeUnauthorized: {
		Message:    "unauthorized",
		StatusCode: http.StatusUnauthorized,
	},
}

type AppError struct {
	code Code
	err  error
}

func (e AppError) Unwrap() error {
	return e.err
}

func (e AppError) Error() string {
	return e.err.Error()
}

func (e AppError) Code() Code {
	return e.code
}

func (e AppError) StatusCode() int {
	return mapCodeToMessage[e.code].StatusCode
}

func WithAppError(err error, code Code) AppError {
	if err == nil {
		err = errors.New(mapCodeToMessage[code].Message)
	}
	return AppError{
		err:  err,
		code: code,
	}
}

func AppErrorFromCode(code Code) AppError {
	return AppError{
		code: code,
		err:  errors.New(mapCodeToMessage[code].Message),
	}
}

var (
	ErrorUsernameOrPasswordInvalid AppError = AppErrorFromCode(CodeUsernameOrPasswordInvalid)
	ErrorInvalidMFAReferenceID     AppError = AppErrorFromCode(CodeInvalidMFAReferenceID)
	ErrorInvalidMFAPrivateKey      AppError = AppErrorFromCode(CodeInvalidMFAPrivateKey)
	ErrorInvalidMFACode            AppError = AppErrorFromCode(CodeInvalidMFACode)
	ErrorBadRequest                AppError = AppErrorFromCode(CodeBadRequest)
	ErrorExceededMFACodeAttempts   AppError = AppErrorFromCode(CodeExceededMFACodeAttempts)
	ErrorMFAForPhoneNotFound       AppError = AppErrorFromCode(CodeMFAForPhoneNotFound)
	ErrorMFAForEmailNotFound       AppError = AppErrorFromCode(CodeMFAForEmailNotFound)
	ErrorUnauthorized              AppError = AppErrorFromCode(CodeUnauthorized)
	ErrorInternalServerError       AppError = AppErrorFromCode(CodeInternalServerError)
	ErrorCacheError                AppError = AppErrorFromCode(CodeCacheError)
	ErrorSendSMSFailed             AppError = AppErrorFromCode(CodeSendSMSFailed)
	ErrorSendEmailFailed           AppError = AppErrorFromCode(CodeSendEmailFailed)
	ErrorTOTPMethodAlreadyExists   AppError = AppErrorFromCode(CodeTOTPMethodAlreadyExists)
)
