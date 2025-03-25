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
	Username        string
	IPAddress       sql.NullString
	UserAgent       sql.NullString
	DeviceID        sql.NullString
	Metadata        map[string]interface{}
	LoginType       string
	LoginStatus     sql.NullString
	IsImpersonation bool
	CreatedAt       time.Time
	UpdatedAt       sql.NullTime
	DeletedAt       sql.NullTime
}
