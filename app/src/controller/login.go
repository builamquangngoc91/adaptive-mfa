package controller

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/bcrypt"
)

type ILoginController interface {
	Login(w http.ResponseWriter, r *http.Request)
	LoginWithMFA(w http.ResponseWriter, r *http.Request)
	SendLoginEmailCode(w http.ResponseWriter, r *http.Request)
	VerifyLoginEmailCode(w http.ResponseWriter, r *http.Request)
	SendLoginPhoneCode(w http.ResponseWriter, r *http.Request)
	VerifyLoginPhoneCode(w http.ResponseWriter, r *http.Request)
}

type LoginController struct {
	cfg               *config.Config
	cache             cache.ICache
	userRepository    repository.IUserRepository
	userMFARepository repository.IUserMFARepository
}

func NewLoginController(
	cfg *config.Config,
	cache cache.ICache,
	userRepository repository.IUserRepository,
	userMFARepository repository.IUserMFARepository,
) ILoginController {
	return &LoginController{
		cfg:               cfg,
		cache:             cache,
		userRepository:    userRepository,
		userMFARepository: userMFARepository,
	}
}

func (h *LoginController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	requestID := ctx.Value(common.ContextKeyRequestID).(string)

	user, err := h.userRepository.GetByUsername(ctx, nil, request.Username)
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

	referenceID := uuid.New().String()
	mfaMetadata := domain.MFAMetadata{
		UserID: user.ID,
	}

	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(requestID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.isRequiredMFA() {
		response := domain.LoginResponse{
			RequiredMFA: true,
			ReferenceID: referenceID,
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	token, err := h.generateToken(ctx, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(domain.LoginResponse{
		Token: token,
	})
}

func (h *LoginController) LoginWithMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.LoginWithMFARequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var metadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if metadata.PrivateKey != request.PrivateKey {
		http.Error(w, "Invalid private key", http.StatusUnauthorized)
		return
	}

	user, err := h.userRepository.GetByID(ctx, nil, metadata.UserID)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := h.cache.Del(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := h.generateToken(ctx, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(domain.LoginWithMFAResponse{
		Token: token,
	})
}

func (h *LoginController) generateToken(ctx context.Context, user *model.User) (string, error) {
	exp := time.Now().Add(time.Hour * 24)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": exp.Unix(),
	}).SignedString([]byte(h.cfg.Jwt))
	if err != nil {
		return "", err
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Set(ctx, cache.GetTokenKey(sha1Token), fmt.Sprintf("%d", exp.UnixMilli()), ptr.ToPtr(time.Hour*24)); err != nil {
		return "", err
	}

	return token, nil
}

func (h *LoginController) SendLoginEmailCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.SendLoginEmailCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &mfaMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeEmail))
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userMfa == nil {
		http.Error(w, "MFA for email not found", http.StatusNotFound)
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Email verification code: %s\n", code)
	w.WriteHeader(http.StatusOK)
}

func (h *LoginController) VerifyLoginEmailCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.VerifyLoginEmailCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &mfaMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code, err := h.cache.Get(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	mfaMetadata.Type = domain.UserMFATypeEmail
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.cache.Del(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := domain.VerifyTOTPCodeResponse{
		ReferenceID: request.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	json.NewEncoder(w).Encode(response)
	w.WriteHeader(http.StatusOK)
}

func (h *LoginController) SendLoginPhoneCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.SendLoginPhoneCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &mfaMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeEmail))
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userMfa == nil {
		http.Error(w, "MFA for phone not found", http.StatusNotFound)
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Phone login code: %s\n", code)
	w.WriteHeader(http.StatusOK)
}

func (h *LoginController) VerifyLoginPhoneCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.VerifyLoginPhoneCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &mfaMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code, err := h.cache.Get(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if code != request.Code {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	mfaMetadata.Type = domain.UserMFATypePhone
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.cache.Del(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := domain.VerifyTOTPCodeResponse{
		ReferenceID: request.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	json.NewEncoder(w).Encode(response)
	w.WriteHeader(http.StatusOK)
}

func (h *LoginController) isRequiredMFA() bool {
	return true
}
