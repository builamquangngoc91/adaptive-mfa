package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

type IUserVerificationController interface {
	SendEmailVerification(w http.ResponseWriter, r *http.Request)
	VerifyEmailVerification(w http.ResponseWriter, r *http.Request)
	SendPhoneVerification(w http.ResponseWriter, r *http.Request)
	VerifyPhoneVerification(w http.ResponseWriter, r *http.Request)
}

type UserVerificationController struct {
	cfg            *config.Config
	userRepository repository.IUserRepository
	cache          cache.ICache
}

func NewUserVerificationController(
	cfg *config.Config,
	cache cache.ICache,
	userRepository repository.IUserRepository,
) IUserVerificationController {
	return &UserVerificationController{
		cfg:            cfg,
		cache:          cache,
		userRepository: userRepository,
	}
}

func (h *UserVerificationController) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetEmailVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Email verification code: %s\n", code)

	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) VerifyEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.VerifyEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID := ctx.Value(common.ContextKeyUserID).(string)
	code, err := h.cache.GetAndDel(ctx, cache.GetEmailVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code || err == cache.Nil {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.userRepository.UpdateEmailVerifiedAt(ctx, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Email verified")
	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) SendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetPhoneVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Phone verification code: %s\n", code)
	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) VerifyPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.VerifyPhoneVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID := ctx.Value(common.ContextKeyUserID).(string)

	code, err := h.cache.GetAndDel(ctx, cache.GetPhoneVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code || err == cache.Nil {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.userRepository.UpdatePhoneVerifiedAt(ctx, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Phone verified")
	w.WriteHeader(http.StatusOK)
}
