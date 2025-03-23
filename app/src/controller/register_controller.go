package controller

import (
	models "adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type IAuthHandler interface {
	Register(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
	SendEmailVerification(w http.ResponseWriter, r *http.Request)
	VerifyEmailVerification(w http.ResponseWriter, r *http.Request)
	SendPhoneVerification(w http.ResponseWriter, r *http.Request)
	VerifyPhoneVerification(w http.ResponseWriter, r *http.Request)
}

type AuthHandler struct {
	cache          cache.ICache
	userRepository repository.IUserRepository
}

func NewAuthHandler(cache cache.ICache, userRepository repository.IUserRepository) IAuthHandler {
	return &AuthHandler{
		cache:          cache,
		userRepository: userRepository,
	}
}

type RegisterRequest struct {
	Fullname string `json:"fullname"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), 14)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newUser := models.User{
		ID:           uuid.New().String(),
		Fullname:     request.Fullname,
		Username:     request.Username,
		HashPassword: string(hashPassword),
		Email:        database.NewNullString(request.Email),
		Phone:        database.NewNullString(request.Phone),
	}

	if err := h.userRepository.Create(ctx, &newUser); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetByUsername(ctx, request.Username)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(request.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	exp := time.Now().Add(time.Hour * 24)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": exp.Unix(),
	}).SignedString([]byte("abc123"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Set(ctx, cache.GetTokenKey(sha1Token), exp.String(), ptr.ToPtr(time.Hour*24)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Del(ctx, cache.GetTokenKey(sha1Token)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
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

func (h *AuthHandler) VerifyEmailVerification(w http.ResponseWriter, r *http.Request) {
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

func (h *AuthHandler) SendPhoneVerification(w http.ResponseWriter, r *http.Request) {
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

func (h *AuthHandler) VerifyPhoneVerification(w http.ResponseWriter, r *http.Request) {
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
