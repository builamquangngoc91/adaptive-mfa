package controller

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/email"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/pkg/sms"
	"adaptive-mfa/repository"

	"github.com/dgrijalva/jwt-go"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/bcrypt"
)

type ILoginController interface {
	Login(context.Context, *domain.LoginRequest) (*domain.LoginResponse, error)
	LoginWithMFA(context.Context, *domain.LoginWithMFARequest) (*domain.LoginResponse, error)
	SendLoginEmailCode(context.Context, *domain.SendLoginEmailCodeRequest) (*domain.SendLoginEmailCodeResponse, error)
	VerifyLoginEmailCode(context.Context, *domain.VerifyLoginEmailCodeRequest) (*domain.VerifyLoginEmailCodeResponse, error)
	SendLoginPhoneCode(context.Context, *domain.SendLoginPhoneCodeRequest) (*domain.SendLoginPhoneCodeResponse, error)
	VerifyLoginPhoneCode(context.Context, *domain.VerifyLoginPhoneCodeRequest) (*domain.VerifyLoginPhoneCodeResponse, error)
}

type LoginController struct {
	cfg               *config.Config
	cache             cache.ICache
	userRepository    repository.IUserRepository
	userMFARepository repository.IUserMFARepository
	emailService      email.IEmail
	smsService        sms.ISMS
}

func NewLoginController(
	cfg *config.Config,
	cache cache.ICache,
	userRepository repository.IUserRepository,
	userMFARepository repository.IUserMFARepository,
	emailService email.IEmail,
	smsService sms.ISMS,
) ILoginController {
	return &LoginController{
		cfg:               cfg,
		cache:             cache,
		userRepository:    userRepository,
		userMFARepository: userMFARepository,
		emailService:      emailService,
		smsService:        smsService,
	}
}

func (h *LoginController) Login(ctx context.Context, req *domain.LoginRequest) (*domain.LoginResponse, error) {
	requestID := common.GetRequestID(ctx)

	user, err := h.userRepository.GetByUsername(ctx, nil, req.Username)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if user == nil {
		return nil, errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid password")
	}

	mfaMetadata := domain.MFAMetadata{
		UserID: user.ID,
	}

	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(requestID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	if h.isRequiredMFA() {
		response := &domain.LoginResponse{
			RequiredMFA: true,
			ReferenceID: requestID,
		}

		return response, nil
	}

	token, err := h.generateToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &domain.LoginResponse{
		Token: token,
	}, nil
}

func (h *LoginController) LoginWithMFA(ctx context.Context, req *domain.LoginWithMFARequest) (*domain.LoginResponse, error) {
	var metadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &metadata); err != nil {
		return nil, err
	}

	if metadata.PrivateKey != req.PrivateKey {
		return nil, errors.New("invalid private key")
	}

	user, err := h.userRepository.GetByID(ctx, nil, metadata.UserID)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if user == nil {
		return nil, errors.New("user not found")
	}

	if err := h.cache.Del(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID)); err != nil {
		return nil, err
	}

	token, err := h.generateToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &domain.LoginResponse{
		Token: token,
	}, nil
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

func (h *LoginController) SendLoginEmailCode(ctx context.Context, req *domain.SendLoginEmailCodeRequest) (*domain.SendLoginEmailCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		return nil, err
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeEmail))
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if userMfa == nil {
		return nil, errors.New("MFA for email not found")
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("Your login verification code is %s", code)
	h.emailService.SendEmail(ctx, userMfa.Metadata.Email, "Login Verification Code", msg)
	return &domain.SendLoginEmailCodeResponse{}, nil
}

func (h *LoginController) VerifyLoginEmailCode(ctx context.Context, req *domain.VerifyLoginEmailCodeRequest) (*domain.VerifyLoginEmailCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		return nil, err
	}

	code, err := h.cache.Get(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID))
	if err != nil {
		return nil, err
	}

	if code != req.Code {
		return nil, errors.New("invalid code")
	}

	mfaMetadata.Type = domain.UserMFATypeEmail
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	if err := h.cache.Del(ctx, cache.GetEmailLoginCodeKey(mfaMetadata.UserID)); err != nil {
		return nil, err
	}

	response := &domain.VerifyLoginEmailCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	return response, nil
}

func (h *LoginController) SendLoginPhoneCode(ctx context.Context, req *domain.SendLoginPhoneCodeRequest) (*domain.SendLoginPhoneCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		return nil, err
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeEmail))
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if userMfa == nil {
		return nil, errors.New("MFA for phone not found")
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("Your login verification code is %s", code)
	h.smsService.SendSMS(ctx, userMfa.Metadata.Phone, msg)
	return &domain.SendLoginPhoneCodeResponse{}, nil
}

func (h *LoginController) VerifyLoginPhoneCode(ctx context.Context, req *domain.VerifyLoginPhoneCodeRequest) (*domain.VerifyLoginPhoneCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		return nil, err
	}

	code, err := h.cache.Get(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID))
	if err != nil {
		return nil, err
	}

	if code != req.Code {
		return nil, errors.New("invalid code")
	}

	mfaMetadata.Type = domain.UserMFATypePhone
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	if err := h.cache.Del(ctx, cache.GetPhoneLoginCodeKey(mfaMetadata.UserID)); err != nil {
		return nil, err
	}

	response := &domain.VerifyLoginPhoneCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	return response, nil
}

func (h *LoginController) isRequiredMFA() bool {
	return true
}
