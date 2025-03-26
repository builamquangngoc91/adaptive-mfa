package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/repository"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type IHackedController interface {
	Disavow(ctx context.Context) (*domain.DisavowResponse, error)
}

type HackedController struct {
	cfg                    *config.Config
	cache                  cache.ICache
	userLoginLogRepository repository.IUserLoginLogRepository
}

func NewHackedController(cfg *config.Config, cache cache.ICache, userLoginLogRepository repository.IUserLoginLogRepository) IHackedController {
	return &HackedController{
		cfg:                    cfg,
		cache:                  cache,
		userLoginLogRepository: userLoginLogRepository,
	}
}

func (h *HackedController) Disavow(ctx context.Context) (*domain.DisavowResponse, error) {
	referenceID := common.GetParams(ctx).Get("ref")
	if referenceID == "" {
		return nil, appError.WithAppError(errors.New("reference ID is required"), appError.CodeBadRequest)
	}

	var mfaMetadata domain.MFAMetadata
	if err := h.cache.GetAndDelJSON(ctx, cache.GetMFAReferenceIDKey(referenceID), &mfaMetadata); err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorInvalidMFAReferenceID
		}
		return nil, err
	}

	userLoginLog := &model.UserLoginLog{
		ID:          uuid.New().String(),
		RequestID:   common.GetRequestID(ctx),
		ReferenceID: database.NewNullString(referenceID),
		UserID:      database.NewNullString(mfaMetadata.UserID),
		IPAddress:   database.NewNullString(common.GetIPAddress(ctx)),
		UserAgent:   database.NewNullString(common.GetUserAgent(ctx)),
		DeviceID:    database.NewNullString(common.GetDeviceID(ctx)),
		LoginType:   string(mfaMetadata.Type),
		LoginStatus: database.NewNullString(string(model.UserLoginStatusDisavowed)),
		Attempts:    mfaMetadata.Attempts,
		CreatedAt:   time.Now(),
	}

	if err := h.userLoginLogRepository.Create(ctx, nil, userLoginLog); err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	return &domain.DisavowResponse{
		Message: "Disavow OK",
	}, nil
}
