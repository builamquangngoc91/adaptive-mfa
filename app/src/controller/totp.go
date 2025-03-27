package controller

import (
	"context"
	"database/sql"
	"errors"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/repository"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/thanhpk/randstr"
)

//go:generate mockgen -source=totp.go -destination=./mock/totp.go -package=mock
type ITOTPController interface {
	AddTOTPMethod(ctx context.Context, req *domain.AddTOTPMethodRequest) (*domain.AddTOTPMethodResponse, error)
	DeleteTOTPMethod(ctx context.Context) (*domain.DeleteTOTPMethodResponse, error)
	VerifyTOTPCode(ctx context.Context, req *domain.VerifyTOTPCodeRequest) (*domain.VerifyTOTPCodeResponse, error)
	ListTOTPMethods(ctx context.Context) (*domain.ListTOTPMethodsResponse, error)
}

type TOTPController struct {
	cfg               *config.Config
	db                database.IDatabase
	cache             cache.ICache
	userMFARepository repository.IUserMFARepository
}

func NewTOTPController(cfg *config.Config, db database.IDatabase, userMFARepository repository.IUserMFARepository, cache cache.ICache) *TOTPController {
	return &TOTPController{
		cfg:               cfg,
		db:                db,
		cache:             cache,
		userMFARepository: userMFARepository,
	}
}

func (c *TOTPController) AddTOTPMethod(ctx context.Context, req *domain.AddTOTPMethodRequest) (*domain.AddTOTPMethodResponse, error) {
	userID := common.GetUserID(ctx)

	existingUserMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if existingUserMFA != nil {
		return nil, appError.ErrorTOTPMethodAlreadyExists
	}

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      c.cfg.TOTP.Issuer,
		AccountName: userID,
		SecretSize:  c.cfg.TOTP.SecretSize,
	})
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if err := c.userMFARepository.Create(ctx, nil, &model.UserMFA{
		ID:      uuid.New().String(),
		UserID:  userID,
		MFAType: model.UserMFATypeOTP,
		Metadata: &model.UserMFAMetaData{
			Secret: totpKey.Secret(),
		},
	}); err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	response := &domain.AddTOTPMethodResponse{
		Secret: totpKey.Secret(),
		Issuer: c.cfg.TOTP.Issuer,
	}

	return response, nil
}

func (c *TOTPController) DeleteTOTPMethod(ctx context.Context) (*domain.DeleteTOTPMethodResponse, error) {
	userID := common.GetUserID(ctx)
	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if userMFA == nil {
		return nil, appError.ErrorMFAForEmailNotFound
	}

	if err := c.userMFARepository.SoftDelete(ctx, nil, userMFA.ID); err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	return &domain.DeleteTOTPMethodResponse{}, nil
}

func (c *TOTPController) VerifyTOTPCode(ctx context.Context, req *domain.VerifyTOTPCodeRequest) (*domain.VerifyTOTPCodeResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, appError.WithAppError(err, appError.CodeBadRequest)
	}

	var mfaMetadata domain.MFAMetadata
	if err := c.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		if !errors.Is(err, cache.Nil) {
			return nil, appError.WithAppError(err, appError.CodeCacheError)
		}
		return nil, appError.ErrorInvalidMFACode
	}

	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}
	if userMFA == nil {
		return nil, appError.ErrorMFAForEmailNotFound
	}

	var valid bool
	key := cache.GetLoginVerificationAttemptsKey(mfaMetadata.UserID, common.GetIPAddress(ctx))
	fn := func() (bool, error) {
		valid = totp.Validate(req.Code, userMFA.Metadata.Secret)
		if !valid {
			IncrementLoginFailedCounter(ctx, mfaMetadata.UserID, common.GetIPAddress(ctx))
		}
		return valid, nil
	}
	err = RateLimit(ctx, c.cache, key, c.cfg.RateLimit.LoginVerificationAttemptsThreshold, c.cfg.RateLimit.LoginVerificationAttemptsLockDuration, fn)
	switch err {
	case nil:
		if !valid {
			return nil, appError.ErrorInvalidMFACode
		}
	case appError.ErrorExceededThresholdRateLimit:
		return nil, appError.ErrorExceededLoginVerificationAttempts
	default:
		return nil, err
	}

	mfaMetadata.Type = domain.UserLoginTypeMFATOTP
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := c.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, nil, true); err != nil {
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	return &domain.VerifyTOTPCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}, nil
}

func (c *TOTPController) ListTOTPMethods(ctx context.Context) (*domain.ListTOTPMethodsResponse, error) {
	userID := common.GetUserID(ctx)
	userMFAs, err := c.userMFARepository.ListByUserID(ctx, nil, userID)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	methods := make([]string, len(userMFAs))
	for i, userMFA := range userMFAs {
		methods[i] = string(userMFA.MFAType)
	}

	response := &domain.ListTOTPMethodsResponse{
		Methods: methods,
	}

	return response, nil
}
