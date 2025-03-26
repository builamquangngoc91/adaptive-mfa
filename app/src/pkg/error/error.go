package error

import "errors"

type Code int

const (
	CodeUsernameOrPasswordInvalid Code = 104000001
	CodeInvalidMFAReferenceID     Code = 104000002
	CodeInvalidMFAPrivateKey      Code = 104000003
	CodeInvalidMFACode            Code = 104000006
	CodeMFAForPhoneNotFound       Code = 104000004
	CodeMFAForEmailNotFound       Code = 104000005
	CodeInternalServerError       Code = 105000001
	CodeCacheError                Code = 105000002
	CodeSendSMSFailed             Code = 105000003
	CodeSendEmailFailed           Code = 105000004
)

var mapCodeToMessage = map[Code]string{
	CodeUsernameOrPasswordInvalid: "username or password invalid",
	CodeInvalidMFAReferenceID:     "invalid mfa reference id",
	CodeInvalidMFAPrivateKey:      "invalid mfa private key",
	CodeInvalidMFACode:            "invalid mfa code",
	CodeMFAForPhoneNotFound:       "mfa for phone not found",
	CodeMFAForEmailNotFound:       "mfa for email not found",
	CodeInternalServerError:       "internal server error",
	CodeCacheError:                "cache error",
	CodeSendSMSFailed:             "send sms failed",
	CodeSendEmailFailed:           "send email failed",
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

func WithAppError(err error, code Code) AppError {
	if err == nil {
		err = errors.New(mapCodeToMessage[code])
	}
	return AppError{
		err:  err,
		code: code,
	}
}

func AppErrorFromCode(code Code) AppError {
	return AppError{
		code: code,
		err:  errors.New(mapCodeToMessage[code]),
	}
}

var (
	ErrorUsernameOrPasswordInvalid AppError = AppErrorFromCode(CodeUsernameOrPasswordInvalid)
	ErrorInvalidMFAReferenceID     AppError = AppErrorFromCode(CodeInvalidMFAReferenceID)
	ErrorInvalidMFAPrivateKey      AppError = AppErrorFromCode(CodeInvalidMFAPrivateKey)
	ErrorInvalidMFACode            AppError = AppErrorFromCode(CodeInvalidMFACode)
	ErrorMFAForPhoneNotFound       AppError = AppErrorFromCode(CodeMFAForPhoneNotFound)
	ErrorMFAForEmailNotFound       AppError = AppErrorFromCode(CodeMFAForEmailNotFound)
	ErrorInternalServerError       AppError = AppErrorFromCode(CodeInternalServerError)
	ErrorCacheError                AppError = AppErrorFromCode(CodeCacheError)
	ErrorSendSMSFailed             AppError = AppErrorFromCode(CodeSendSMSFailed)
	ErrorSendEmailFailed           AppError = AppErrorFromCode(CodeSendEmailFailed)
)
