package model

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

type UserLoginLogs []*UserLoginLog

type UserLoginLog struct {
	ID          string
	RequestID   string
	ReferenceID sql.NullString
	UserID      sql.NullString
	IPAddress   sql.NullString
	UserAgent   sql.NullString
	DeviceID    sql.NullString
	Metadata    *UserLoginMetadata
	LoginType   string
	LoginStatus sql.NullString
	Attempts    int
	RequiredMFA bool
	CreatedAt   time.Time
	UpdatedAt   sql.NullTime
	DeletedAt   sql.NullTime
}

type UserLoginType string

const (
	UserLoginTypeBasicAuth UserLoginType = "basic_auth"
	UserLoginTypeMFAMail   UserLoginType = "mfa_mail"
	UserLoginTypeMFASMS    UserLoginType = "mfa_sms"
	UserLoginTypeMFATOTP   UserLoginType = "mfa_totp"
)

type UserLoginStatus string

const (
	UserLoginStatusSuccess   UserLoginStatus = "success"
	UserLoginStatusFailed    UserLoginStatus = "failed"
	UserLoginStatusVerified  UserLoginStatus = "verified"
	UserLoginStatusDisavowed UserLoginStatus = "disavowed"
)

type UserLoginMetadata struct {
	Username string `json:"username,omitempty"`
}

func (m *UserLoginMetadata) Value() (driver.Value, error) {
	return json.Marshal(m)
}

func (m *UserLoginMetadata) Scan(value interface{}) error {
	metadata, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(metadata, m)
}

type UserLoginLogAnalysis struct {
	LatestSuccessFromIP  sql.NullTime
	LatestSuccess        sql.NullTime
	CountAttemptsFromIP  sql.NullInt64
	CountAttempts        sql.NullInt64
	CountDisavowedFromIP sql.NullInt64
}
