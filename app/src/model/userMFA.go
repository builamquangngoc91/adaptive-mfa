package model

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
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
	Phone  string `json:"phone,omitempty"`
	Email  string `json:"email,omitempty"`
	Secret string `json:"secret,omitempty"`
}

func (s *UserMFAMetaData) Value() (driver.Value, error) {
	return json.Marshal(s)
}

func (s *UserMFAMetaData) Scan(value interface{}) error {
	metadata, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(metadata, s)
}
