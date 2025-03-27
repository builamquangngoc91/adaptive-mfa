package domain

import "errors"

type RegisterRequest struct {
	Fullname string `json:"fullname"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

func (r RegisterRequest) Validate() error {
	if r.Fullname == "" {
		return errors.New("fullname is required")
	}

	if r.Username == "" {
		return errors.New("username is required")
	}

	if r.Password == "" {
		return errors.New("password is required")
	}

	return nil
}

type RegisterResponse struct{}
