package model

import (
	"database/sql"
	"time"
)

type UserLoginLogs []*UserLoginLog

type UserLoginLog struct {
	ID              string
	RequestID       string
	ReferenceID     sql.NullString
	UserID          sql.NullString
	IPAddress       sql.NullString
	UserAgent       sql.NullString
	DeviceID        sql.NullString
	Metadata        map[string]interface{}
	LoginType       string
	LoginStatus     sql.NullString
	IsImpersonation bool
	Attempts        int
	CreatedAt       time.Time
	UpdatedAt       sql.NullTime
	DeletedAt       sql.NullTime
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
	UserLoginStatusSuccess UserLoginStatus = "success"
	UserLoginStatusFailed  UserLoginStatus = "failed"
)
