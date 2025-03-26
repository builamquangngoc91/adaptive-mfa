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
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/email"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/pkg/logger"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/pkg/sms"
	"adaptive-mfa/repository"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=login.go -destination=./mock/login.go -package=mock
type ILoginController interface {
	Login(context.Context, *domain.LoginRequest) (*domain.LoginResponse, error)
	LoginWithMFA(context.Context, *domain.LoginWithMFARequest) (*domain.LoginWithMFAResponse, error)
	SendLoginEmailCode(context.Context, *domain.SendLoginEmailCodeRequest) (*domain.SendLoginEmailCodeResponse, error)
	VerifyLoginEmailCode(context.Context, *domain.VerifyLoginEmailCodeRequest) (*domain.VerifyLoginEmailCodeResponse, error)
	SendLoginPhoneCode(context.Context, *domain.SendLoginPhoneCodeRequest) (*domain.SendLoginPhoneCodeResponse, error)
	VerifyLoginPhoneCode(context.Context, *domain.VerifyLoginPhoneCodeRequest) (*domain.VerifyLoginPhoneCodeResponse, error)
}

type LoginController struct {
	cfg                    *config.Config
	cache                  cache.ICache
	userRepository         repository.IUserRepository
	userMFARepository      repository.IUserMFARepository
	userLoginLogRepository repository.IUserLoginLogRepository
	emailService           email.IEmail
	smsService             sms.ISMS
}

func NewLoginController(
	cfg *config.Config,
	cache cache.ICache,
	userRepository repository.IUserRepository,
	userMFARepository repository.IUserMFARepository,
	userLoginLogRepository repository.IUserLoginLogRepository,
	emailService email.IEmail,
	smsService sms.ISMS,
) ILoginController {
	return &LoginController{
		cfg:                    cfg,
		cache:                  cache,
		userRepository:         userRepository,
		userMFARepository:      userMFARepository,
		userLoginLogRepository: userLoginLogRepository,
		emailService:           emailService,
		smsService:             smsService,
	}
}

func (h *LoginController) Login(ctx context.Context, req *domain.LoginRequest) (_ *domain.LoginResponse, err error) {
	var (
		user        *model.User
		requiredMFA bool
	)

	defer func() {
		var userID sql.NullString
		if user != nil {
			userID = database.NewNullString(user.ID)
		}
		userLoginLog := &model.UserLoginLog{
			ID:          uuid.New().String(),
			RequestID:   common.GetRequestID(ctx),
			UserID:      userID,
			IPAddress:   database.NewNullString(common.GetIPAddress(ctx)),
			UserAgent:   database.NewNullString(common.GetUserAgent(ctx)),
			DeviceID:    database.NewNullString(common.GetDeviceID(ctx)),
			LoginType:   string(model.UserLoginTypeBasicAuth),
			RequiredMFA: requiredMFA,
			CreatedAt:   time.Now(),
		}

		switch err {
		case appError.ErrorUsernameOrPasswordInvalid:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusFailed))
		case nil:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusSuccess))
		default:
			// no-op
			return
		}

		if _err := h.userLoginLogRepository.Create(ctx, nil, userLoginLog); _err != nil {
			logger.NewLogger().
				WithContext(ctx).
				With("error", _err).
				Error("Failed to create user login log")
		}
	}()

	requestID := common.GetRequestID(ctx)
	user, err = h.userRepository.GetByUsername(ctx, nil, req.Username)
	if err != nil && err != sql.ErrNoRows {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if user == nil {
		return nil, appError.ErrorUsernameOrPasswordInvalid
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(req.Password))
	if err != nil {
		return nil, appError.ErrorUsernameOrPasswordInvalid
	}

	mfaMetadata := domain.MFAMetadata{
		UserID:   user.ID,
		Username: user.Username,
	}

	err = h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(requestID), mfaMetadata, ptr.ToPtr(time.Minute*5), false)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	requiredMFA, err = h.isRequiredMFA(ctx, user.ID, common.GetIPAddress(ctx))
	if err != nil {
		return nil, err
	}

	if requiredMFA {
		return &domain.LoginResponse{
			RequiredMFA: requiredMFA,
			ReferenceID: requestID,
		}, nil
	}

	var token string
	token, err = h.generateToken(ctx, user)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	return &domain.LoginResponse{
		Token: token,
	}, nil
}

func (h *LoginController) LoginWithMFA(ctx context.Context, req *domain.LoginWithMFARequest) (_ *domain.LoginWithMFAResponse, err error) {
	var (
		metadata domain.MFAMetadata
		user     *model.User
		token    string
	)

	defer func() {
		var userID sql.NullString
		if user != nil {
			userID = database.NewNullString(user.ID)
		}
		userLoginLog := &model.UserLoginLog{
			ID:          uuid.New().String(),
			RequestID:   common.GetRequestID(ctx),
			ReferenceID: database.NewNullString(req.ReferenceID),
			UserID:      userID,
			IPAddress:   database.NewNullString(common.GetIPAddress(ctx)),
			UserAgent:   database.NewNullString(common.GetUserAgent(ctx)),
			DeviceID:    database.NewNullString(common.GetDeviceID(ctx)),
			LoginType:   string(metadata.Type),
			CreatedAt:   time.Now(),
		}

		switch err {
		case appError.ErrorInvalidMFAPrivateKey:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusFailed))
		case nil:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusSuccess))
		default:
			// no-op
			return
		}

		if _err := h.userLoginLogRepository.Create(ctx, nil, userLoginLog); _err != nil {
			logger.NewLogger().
				WithContext(ctx).
				With("error", _err).
				Error("Failed to create user login log")
		}
	}()

	err = h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &metadata)
	if err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	if metadata.PrivateKey != req.PrivateKey {
		return nil, appError.ErrorInvalidMFAPrivateKey
	}

	user, err = h.userRepository.GetByID(ctx, nil, metadata.UserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if user == nil {
		return nil, appError.WithAppError(errors.New("user not found"), appError.CodeInternalServerError)
	}

	err = h.cache.Del(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID))
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	token, err = h.generateToken(ctx, user)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	return &domain.LoginWithMFAResponse{
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
	if err := h.cache.Set(ctx, cache.GetTokenKey(sha1Token), fmt.Sprintf("%d", exp.UnixMilli()), ptr.ToPtr(time.Hour*24), false); err != nil {
		return "", err
	}

	return token, nil
}

func (h *LoginController) SendLoginEmailCode(ctx context.Context, req *domain.SendLoginEmailCodeRequest) (*domain.SendLoginEmailCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeEmail))
	if err != nil && err != sql.ErrNoRows {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if userMfa == nil {
		return nil, appError.ErrorMFAForEmailNotFound
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	mfaMetadata.Code = code
	mfaMetadata.Type = domain.UserLoginTypeMFAMail
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true); err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	disavowURL := fmt.Sprintf("%s?ref=%s", h.cfg.DisavowURL, req.ReferenceID)
	msg := fmt.Sprintf("Your login verification code is %s, If you did not request this code please click link %s", code, disavowURL)
	if err := h.emailService.SendEmail(ctx, userMfa.Metadata.Email, "Login Verification Code", msg); err != nil {
		return nil, appError.WithAppError(err, appError.CodeSendEmailFailed)
	}
	if h.cfg.Env != string(common.Production) {
		return &domain.SendLoginEmailCodeResponse{
			Code:       code,
			DisavowURL: disavowURL,
		}, nil
	}
	return &domain.SendLoginEmailCodeResponse{}, nil
}

func (h *LoginController) VerifyLoginEmailCode(ctx context.Context, req *domain.VerifyLoginEmailCodeRequest) (_ *domain.VerifyLoginEmailCodeResponse, err error) {
	var mfaMetadata domain.MFAMetadata

	defer func() {
		userLoginLog := &model.UserLoginLog{
			ID:          uuid.New().String(),
			RequestID:   common.GetRequestID(ctx),
			ReferenceID: database.NewNullString(req.ReferenceID),
			UserID:      database.NewNullString(mfaMetadata.UserID),
			IPAddress:   database.NewNullString(common.GetIPAddress(ctx)),
			UserAgent:   database.NewNullString(common.GetUserAgent(ctx)),
			DeviceID:    database.NewNullString(common.GetDeviceID(ctx)),
			LoginType:   string(model.UserLoginTypeMFAMail),
			CreatedAt:   time.Now(),
		}

		switch err {
		case appError.ErrorInvalidMFACode:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusFailed))
		case nil:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusVerified))
		default:
			// no-op
			return
		}

		if _err := h.userLoginLogRepository.Create(ctx, nil, userLoginLog); _err != nil {
			logger.NewLogger().
				WithContext(ctx).
				With("error", _err).
				Error("Failed to create user login log")
		}
	}()

	err = h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata)
	if err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	if mfaMetadata.Code != req.Code {
		mfaMetadata.Attempts++
		if mfaMetadata.Attempts >= 5 {
			return nil, appError.ErrorExceededMFACodeAttempts
		}

		err = h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true)
		if err != nil {
			return nil, err
		}

		return nil, appError.ErrorInvalidMFACode
	}

	mfaMetadata.Type = domain.UserLoginTypeMFAMail
	mfaMetadata.PrivateKey = randstr.Hex(16)
	err = h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	return &domain.VerifyLoginEmailCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}, nil
}

func (h *LoginController) SendLoginPhoneCode(ctx context.Context, req *domain.SendLoginPhoneCodeRequest) (_ *domain.SendLoginPhoneCodeResponse, err error) {
	var mfaMetadata domain.MFAMetadata
	err = h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata)
	if err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	userMfa, err := h.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypePhone))
	if err != nil && err != sql.ErrNoRows {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if userMfa == nil {
		return nil, appError.ErrorMFAForPhoneNotFound
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	mfaMetadata.Code = code
	mfaMetadata.Type = domain.UserLoginTypeMFASMS
	if err := h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true); err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	disavowURL := fmt.Sprintf("%s?ref=%s", h.cfg.DisavowURL, req.ReferenceID)
	msg := fmt.Sprintf("Your login verification code is %s, If you did not request this code please click link %s", code, disavowURL)
	if err := h.smsService.SendSMS(ctx, userMfa.Metadata.Phone, msg); err != nil {
		return nil, appError.WithAppError(err, appError.CodeSendSMSFailed)
	}

	if h.cfg.Env != string(common.Production) {
		return &domain.SendLoginPhoneCodeResponse{
			Code:       code,
			DisavowURL: disavowURL,
		}, nil
	}
	return &domain.SendLoginPhoneCodeResponse{}, nil
}

func (h *LoginController) VerifyLoginPhoneCode(ctx context.Context, req *domain.VerifyLoginPhoneCodeRequest) (_ *domain.VerifyLoginPhoneCodeResponse, err error) {
	var mfaMetadata domain.MFAMetadata

	defer func() {
		userLoginLog := &model.UserLoginLog{
			ID:          uuid.New().String(),
			RequestID:   common.GetRequestID(ctx),
			ReferenceID: database.NewNullString(req.ReferenceID),
			UserID:      database.NewNullString(mfaMetadata.UserID),
			IPAddress:   database.NewNullString(common.GetIPAddress(ctx)),
			UserAgent:   database.NewNullString(common.GetUserAgent(ctx)),
			DeviceID:    database.NewNullString(common.GetDeviceID(ctx)),
			LoginType:   string(model.UserLoginTypeMFASMS),
			Attempts:    mfaMetadata.Attempts,
			CreatedAt:   time.Now(),
		}

		switch err {
		case appError.ErrorInvalidMFACode:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusFailed))
		case nil:
			userLoginLog.LoginStatus = database.NewNullString(string(model.UserLoginStatusVerified))
		default:
			// no-op
			return
		}

		if _err := h.userLoginLogRepository.Create(ctx, nil, userLoginLog); _err != nil {
			logger.NewLogger().
				WithContext(ctx).
				With("error", _err).
				Error("Failed to create user login log")
		}
	}()

	err = h.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata)
	if err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	mfaMetadata.Type = domain.UserLoginTypeMFASMS
	if mfaMetadata.Code != req.Code {
		mfaMetadata.Attempts++
		if mfaMetadata.Attempts >= 5 {
			return nil, appError.ErrorExceededMFACodeAttempts
		}

		err = h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true)
		if err != nil {
			return nil, err
		}

		return nil, appError.ErrorInvalidMFACode
	}

	mfaMetadata.PrivateKey = randstr.Hex(16)
	err = h.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true)
	if err != nil {
		return nil, err
	}

	return &domain.VerifyLoginPhoneCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}, nil
}

func (h *LoginController) isRequiredMFA(ctx context.Context, userID string, ipAddress string) (bool, error) {
	analysis, err := h.userLoginLogRepository.GetAnalysis(ctx, nil, userID, ipAddress)
	if err != nil {
		return false, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if !analysis.CountDisavowedFromIP.Valid || analysis.CountDisavowedFromIP.Int64 > 0 {
		return true, nil
	}

	if !analysis.LatestSuccess.Valid {
		return true, nil
	}

	if analysis.CountAttemptsFromIP.Int64 >= 5 {
		return true, nil
	}

	if analysis.CountAttempts.Int64 >= 10 {
		return true, nil
	}

	if !analysis.LatestSuccessFromIP.Valid || analysis.LatestSuccessFromIP.Time.Before(time.Now().Add(-time.Hour*24)) {
		return true, nil
	}

	return false, nil
}
