package handlers

import (
	"adaptive-mfa/repositories"
	"net/http"
)

var _ IVerificationHandler = &VerificationHandler{}

type IVerificationHandler interface {
	SendVerificationCode(w http.ResponseWriter, r *http.Request)
	VerifyVerificationCode(w http.ResponseWriter, r *http.Request)
}

type VerificationHandler struct {
	userRepository repositories.IUserRepository
}

func NewVerificationHandler(userRepository repositories.IUserRepository) *VerificationHandler {
	return &VerificationHandler{userRepository: userRepository}
}

func (h *VerificationHandler) SendVerificationCode(w http.ResponseWriter, r *http.Request) {
	
}

func (h *VerificationHandler) VerifyVerificationCode(w http.ResponseWriter, r *http.Request) {
}
