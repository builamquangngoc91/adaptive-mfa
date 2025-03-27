package controller

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	"adaptive-mfa/pkg/common"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/repository/mock"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestTOTPController_AddTOTPMethod(t *testing.T) {
	type testcase struct {
		name       string
		ctx        context.Context
		req        *domain.AddTOTPMethodRequest
		controller *TOTPController
		err        error
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.controller.AddTOTPMethod(tc.ctx, tc.req)
			assert.Equal(t, tc.err, err)
		})
	}

	userID := uuid.New().String()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyUserID, userID)

	validate(t, &testcase{
		name: "error: GetByUserIDAndMFAType failed",
		ctx:  ctx,
		req:  &domain.AddTOTPMethodRequest{},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(nil, sql.ErrConnDone)
			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "error: UserMFA already exists",
		ctx:  ctx,
		req:  &domain.AddTOTPMethodRequest{},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(&model.UserMFA{
					ID:      uuid.New().String(),
					UserID:  userID,
					MFAType: model.UserMFATypeOTP,
				}, nil)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.ErrorTOTPMethodAlreadyExists,
	})

	validate(t, &testcase{
		name: "error: Create failed",
		ctx:  ctx,
		req:  &domain.AddTOTPMethodRequest{},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(nil, nil)

			userMFARepository.
				EXPECT().
				Create(ctx, nil, gomock.Any()).
				Return(sql.ErrConnDone)

			return NewTOTPController(&config.Config{
				TOTP: &config.TOTPConfig{
					SecretSize: 20,
					Issuer:     "test",
				},
			}, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})
}

func TestTOTPController_DeleteTOTPMethod(t *testing.T) {
	type testcase struct {
		name       string
		ctx        context.Context
		controller *TOTPController
		err        error
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.controller.DeleteTOTPMethod(tc.ctx)
			assert.Equal(t, tc.err, err)
		})
	}

	userID := uuid.New().String()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyUserID, userID)

	validate(t, &testcase{
		name: "error: GetByUserIDAndMFAType failed",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(nil, sql.ErrConnDone)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "error: UserMFA not found",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(nil, nil)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.ErrorMFAForEmailNotFound,
	})
	validate(t, &testcase{
		name: "error: SoftDelete failed",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(&model.UserMFA{}, nil)

			userMFARepository.
				EXPECT().
				SoftDelete(ctx, nil, gomock.Any()).
				Return(sql.ErrConnDone)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP)).
				Return(&model.UserMFA{}, nil)

			userMFARepository.
				EXPECT().
				SoftDelete(ctx, nil, gomock.Any()).
				Return(nil)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
	})
}

func TestTOTPController_VerifyTOTPCode(t *testing.T) {
	type testcase struct {
		name       string
		ctx        context.Context
		req        *domain.VerifyTOTPCodeRequest
		controller *TOTPController
		err        error
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.controller.VerifyTOTPCode(tc.ctx, tc.req)
			assert.Equal(t, tc.err, err)
		})
	}

	userID := uuid.New().String()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyUserID, userID)

	validate(t, &testcase{
		name: "error: Validate failed",
		ctx:  ctx,
		req:  &domain.VerifyTOTPCodeRequest{},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(errors.New("reference ID is required"), appError.CodeBadRequest),
	})

	validate(t, &testcase{
		name: "error: UserMFA not found",
		ctx:  ctx,
		req: &domain.VerifyTOTPCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			_cache := cacheMock.NewMockICache(ctrl)

			_cache.
				EXPECT().
				GetJSON(ctx, gomock.Any(), gomock.Any()).
				Return(cache.Nil)

			return NewTOTPController(nil, nil, nil, _cache)
		}(),
		err: appError.ErrorInvalidMFACode,
	})

	validate(t, &testcase{
		name: "error: GetByUserIDAndMFAType failed",
		ctx:  ctx,
		req: &domain.VerifyTOTPCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)
			_cache := cacheMock.NewMockICache(ctrl)

			_cache.
				EXPECT().
				GetJSON(ctx, gomock.Any(), &domain.MFAMetadata{}).
				Return(nil)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, gomock.Any(), string(model.UserMFATypeOTP)).
				Return(nil, sql.ErrConnDone)

			return NewTOTPController(nil, nil, userMFARepository, _cache)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "error: GetByUserIDAndMFAType failed",
		ctx:  ctx,
		req: &domain.VerifyTOTPCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)
			_cache := cacheMock.NewMockICache(ctrl)

			_cache.
				EXPECT().
				GetJSON(ctx, gomock.Any(), &domain.MFAMetadata{}).
				Return(nil)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, gomock.Any(), string(model.UserMFATypeOTP)).
				Return(nil, sql.ErrConnDone)

			return NewTOTPController(nil, nil, userMFARepository, _cache)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "error: MFA not found",
		ctx:  ctx,
		req: &domain.VerifyTOTPCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)
			_cache := cacheMock.NewMockICache(ctrl)

			_cache.
				EXPECT().
				GetJSON(ctx, gomock.Any(), &domain.MFAMetadata{}).
				Return(nil)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, gomock.Any(), string(model.UserMFATypeOTP)).
				Return(nil, nil)

			return NewTOTPController(nil, nil, userMFARepository, _cache)
		}(),
		err: appError.ErrorMFAForEmailNotFound,
	})

	var code string
	validate(t, &testcase{
		name: "error: Invalid code",
		ctx:  ctx,
		req: &domain.VerifyTOTPCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        code,
		},
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)
			_cache := cacheMock.NewMockICache(ctrl)

			totpKey, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "test",
				AccountName: userID,
				SecretSize:  20,
			})
			secret := totpKey.Secret()
			code, _ = totp.GenerateCode(secret, time.Now().UTC())

			assert.NoError(t, err)
			_cache.
				EXPECT().
				GetJSON(ctx, gomock.Any(), &domain.MFAMetadata{}).
				Return(nil)

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(ctx, nil, gomock.Any(), string(model.UserMFATypeOTP)).
				Return(&model.UserMFA{
					ID:      uuid.New().String(),
					UserID:  userID,
					MFAType: model.UserMFATypeOTP,
					Metadata: &model.UserMFAMetaData{
						Secret: secret,
					},
				}, nil)

			_cache.
				EXPECT().
				Get(ctx, gomock.Any()).
				Return("", cache.Nil)

			_cache.
				EXPECT().
				Del(ctx, gomock.Any()).
				Return(nil)

			_cache.
				EXPECT().
				SetJSON(ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewTOTPController(&config.Config{
				TOTP: &config.TOTPConfig{
					SecretSize: 20,
					Issuer:     "test",
				},
				RateLimit: &config.RateLimitConfig{
					LoginVerificationAttemptsThreshold:    10,
					LoginVerificationAttemptsLockDuration: time.Minute,
				},
			}, nil, userMFARepository, _cache)
		}(),
	})
}

func TestTOTPController_ListMFAMethods(t *testing.T) {
	type testcase struct {
		name       string
		ctx        context.Context
		controller *TOTPController
		err        error
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.controller.ListMFAMethods(tc.ctx)
			assert.Equal(t, tc.err, err)
		})
	}

	userID := uuid.New().String()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyUserID, userID)

	validate(t, &testcase{
		name: "error: List failed",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				ListByUserID(ctx, nil, userID).
				Return(nil, sql.ErrConnDone)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
		err: appError.WithAppError(sql.ErrConnDone, appError.CodeInternalServerError),
	})

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		controller: func() *TOTPController {
			ctrl := gomock.NewController(t)
			userMFARepository := mock.NewMockIUserMFARepository(ctrl)

			userMFARepository.
				EXPECT().
				ListByUserID(ctx, nil, userID).
				Return([]*model.UserMFA{
					{
						ID:      uuid.New().String(),
						UserID:  userID,
						MFAType: model.UserMFATypeOTP,
					},
				}, nil)

			return NewTOTPController(nil, nil, userMFARepository, nil)
		}(),
	})

}
