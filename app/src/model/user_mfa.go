package model

import (
	"database/sql"
	"time"
)

type UserMFAType string

const (
	UserMFATypePhone UserMFAType = "phone"
	UserMFATypeEmail UserMFAType = "email"
	UserMFATypeOTP   UserMFAType = "otp"
)

type UserMFA struct {
	ID        string
	UserID    string
	MFAType   UserMFAType
	Metadata  *UserMFAMetaData
	CreatedAt time.Time
	UpdatedAt sql.NullTime
	DeletedAt sql.NullTime
}

type UserMFAMetaData struct {
	Phone  string `json:"phone"`
	Email  string `json:"email"`
	Secret string `json:"secret"`
}
