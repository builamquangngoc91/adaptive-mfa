package controller

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/thanhpk/randstr"
)

type ITOTPController interface {
	AddTOTPMethod(ctx context.Context, req *domain.AddTOTPMethodRequest) (*domain.AddTOTPMethodResponse, error)
	DeleteTOTPMethod(ctx context.Context, req *domain.DeleteTOTPMethodRequest) (*domain.DeleteTOTPMethodResponse, error)
	VerifyTOTPCode(ctx context.Context, req *domain.VerifyTOTPCodeRequest) (*domain.VerifyTOTPCodeResponse, error)
	ListTOTPMethods(ctx context.Context, req *domain.ListTOTPMethodsRequest) (*domain.ListTOTPMethodsResponse, error)
}

type TOTPController struct {
	db                database.IDatabase
	cache             cache.ICache
	userMFARepository repository.IUserMFARepository
}

func NewTOTPController(db database.IDatabase, userMFARepository repository.IUserMFARepository, cache cache.ICache) *TOTPController {
	return &TOTPController{
		db:                db,
		cache:             cache,
		userMFARepository: userMFARepository,
	}
}

func (c *TOTPController) AddTOTPMethod(ctx context.Context, req *domain.AddTOTPMethodRequest) (*domain.AddTOTPMethodResponse, error) {
	userID := common.GetUserID(ctx)

	existingUserMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if existingUserMFA != nil {
		return nil, errors.New("TOTP method already exists")
	}

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Adaptive MFA",
		AccountName: userID,
		SecretSize:  12,
	})
	if err != nil {
		return nil, err
	}

	if err := c.userMFARepository.Create(ctx, nil, &model.UserMFA{
		ID:      uuid.New().String(),
		UserID:  userID,
		MFAType: model.UserMFATypeOTP,
		Metadata: &model.UserMFAMetaData{
			Secret: totpKey.Secret(),
		},
	}); err != nil {
		return nil, err
	}

	response := &domain.AddTOTPMethodResponse{
		Secret: totpKey.Secret(),
		Issuer: "Adaptive MFA",
	}

	return response, nil
}

func (c *TOTPController) DeleteTOTPMethod(ctx context.Context, req *domain.DeleteTOTPMethodRequest) (*domain.DeleteTOTPMethodResponse, error) {
	userID := common.GetUserID(ctx)
	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil {
		return nil, err
	}

	if userMFA == nil {
		return nil, errors.New("TOTP method not found")
	}

	if err := c.userMFARepository.SoftDelete(ctx, nil, userMFA.ID); err != nil {
		return nil, err
	}

	return &domain.DeleteTOTPMethodResponse{}, nil
}

func (c *TOTPController) VerifyTOTPCode(ctx context.Context, req *domain.VerifyTOTPCodeRequest) (*domain.VerifyTOTPCodeResponse, error) {
	var mfaMetadata domain.MFAMetadata
	if err := c.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), &mfaMetadata); err != nil {
		return nil, err
	}

	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if userMFA == nil {
		return nil, errors.New("TOTP method not found")
	}

	valid := totp.Validate(req.Code, userMFA.Metadata.Secret)
	if !valid {
		return nil, errors.New("invalid TOTP code")
	}

	mfaMetadata.Type = domain.UserLoginTypeMFATOTP
	mfaMetadata.PrivateKey = randstr.Hex(16)
	if err := c.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(req.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		return nil, err
	}

	response := &domain.VerifyTOTPCodeResponse{
		ReferenceID: req.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	return response, nil
}

func (c *TOTPController) ListTOTPMethods(ctx context.Context, req *domain.ListTOTPMethodsRequest) (*domain.ListTOTPMethodsResponse, error) {
	userID := common.GetUserID(ctx)
	userMFAs, err := c.userMFARepository.ListByUserID(ctx, nil, userID)
	if err != nil {
		return nil, err
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
