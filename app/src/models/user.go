package models

import (
	"database/sql"
	"time"
)

type Users []*User

type User struct {
	ID              string
	Fullname        string
	Username        string
	Email           sql.NullString
	Phone           sql.NullString
	HashPassword    string
	EmailVerifiedAt sql.NullTime
	PhoneVerifiedAt sql.NullTime
	CreatedAt       time.Time
	UpdatedAt       sql.NullTime
	DeletedAt       sql.NullTime
}
