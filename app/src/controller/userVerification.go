package controller

import (
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type IUserVerificationController interface {
	SendEmailVerification(w http.ResponseWriter, r *http.Request)
	VerifyEmailVerification(w http.ResponseWriter, r *http.Request)
	SendPhoneVerification(w http.ResponseWriter, r *http.Request)
	VerifyPhoneVerification(w http.ResponseWriter, r *http.Request)
}

type UserVerificationController struct {
	userRepository repository.IUserRepository
	cache          cache.ICache
}

func NewUserVerificationController(
	cache cache.ICache,
	userRepository repository.IUserRepository,
) IUserVerificationController {
	return &UserVerificationController{
		cache:          cache,
		userRepository: userRepository,
	}
}

func (h *UserVerificationController) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("abc123"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims["sub"].(string)
	user, err := h.userRepository.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = user

	code := fmt.Sprintf("%06d", rand.Intn(999999))

	if err := h.cache.Set(ctx, cache.GetEmailVerificationCodeKey(user.ID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Email verification code: %s\n", code)

	w.WriteHeader(http.StatusOK)
}

type VerifyEmailVerificationRequest struct {
	Code string `json:"code"`
}

func (h *UserVerificationController) VerifyEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request VerifyEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("abc123"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims["sub"].(string)
	user, err := h.userRepository.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code, err := h.cache.GetAndDel(ctx, cache.GetEmailVerificationCodeKey(user.ID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code || err == cache.Nil {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.userRepository.UpdateEmailVerifiedAt(ctx, user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Email verified")

	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) SendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("abc123"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims["sub"].(string)
	user, err := h.userRepository.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = user

	code := fmt.Sprintf("%06d", rand.Intn(999999))

	if err := h.cache.Set(ctx, cache.GetEmailVerificationCodeKey(user.ID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Phone verification code: %s\n", code)

	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) VerifyPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request VerifyEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("abc123"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims["sub"].(string)
	user, err := h.userRepository.GetByID(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code, err := h.cache.GetAndDel(ctx, cache.GetPhoneVerificationCodeKey(user.ID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code || err == cache.Nil {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if err := h.userRepository.UpdatePhoneVerifiedAt(ctx, user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Phone verified")

	w.WriteHeader(http.StatusOK)
}
