package controller

import (
	"context"
	"testing"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	"adaptive-mfa/pkg/common"
	emailMock "adaptive-mfa/pkg/email/mock"
	smsMock "adaptive-mfa/pkg/sms/mock"
	repositoryMock "adaptive-mfa/repository/mock"
	"adaptive-mfa/usecase"
	usecaseMock "adaptive-mfa/usecase/mock"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginController_Login(t *testing.T) {
	type testcase struct {
		name            string
		err             error
		ctx             context.Context
		loginController ILoginController
		loginRequest    *domain.LoginRequest
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.Login(tc.ctx, tc.loginRequest)
			assert.Equal(t, tc.err, err)
		})
	}

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		loginRequest: &domain.LoginRequest{
			Username: "test",
			Password: "password",
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				RateLimit: &config.RateLimitConfig{
					LoginAttemptsThreshold:    5,
					LoginAttemptsLockDuration: time.Minute * 10,
				},
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			riskAssessmentUsecase := usecaseMock.NewMockIRiskAssessmentUsecase(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			hashPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), 10)
			userRepository.
				EXPECT().
				GetByUsername(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.User{
					ID:           uuid.New().String(),
					Username:     "test",
					HashPassword: string(hashPassword),
				}, nil)

			_cacheMock.
				EXPECT().
				Get(gomock.Any(), gomock.Any()).
				Return("", cache.Nil)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(nil)

			riskAssessmentUsecase.
				EXPECT().
				CalculateScore(gomock.Any(), gomock.Any()).
				Return(usecase.RiskAssessmentLevelLow, nil)

			_cacheMock.
				EXPECT().
				Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, riskAssessmentUsecase, emailService, smsService)
		}(),
	})
}

func TestLoginController_LoginWithMFA(t *testing.T) {
	type testcase struct {
		name                string
		err                 error
		ctx                 context.Context
		loginController     ILoginController
		loginWithMFARequest *domain.LoginWithMFARequest
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.LoginWithMFA(tc.ctx, tc.loginWithMFARequest)
			assert.Equal(t, tc.err, err)
		})
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		loginWithMFARequest: &domain.LoginWithMFARequest{
			ReferenceID: uuid.New().String(),
			PrivateKey:  "private_key",
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				RateLimit: &config.RateLimitConfig{
					LoginAttemptsThreshold:    5,
					LoginAttemptsLockDuration: time.Minute * 10,
				},
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			_cacheMock.
				EXPECT().
				GetJSON(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&domain.MFAMetadata{})).
				DoAndReturn(func(ctx context.Context, _ string, metadata *domain.MFAMetadata) error {
					metadata.UserID = uuid.New().String()
					metadata.PrivateKey = "private_key"
					return nil
				})

			userRepository.
				EXPECT().
				GetByID(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.User{
					ID: uuid.New().String(),
				}, nil)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(nil)

			_cacheMock.
				EXPECT().
				Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, nil, emailService, smsService)
		}(),
	})
}

func TestLoginController_SendLoginEmailCode(t *testing.T) {
	type testcase struct {
		name                      string
		err                       error
		ctx                       context.Context
		sendLoginEmailCodeRequest *domain.SendLoginEmailCodeRequest
		loginController           ILoginController
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.SendLoginEmailCode(tc.ctx, tc.sendLoginEmailCodeRequest)
			assert.Equal(t, tc.err, err)
		})
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		sendLoginEmailCodeRequest: &domain.SendLoginEmailCodeRequest{
			ReferenceID: uuid.New().String(),
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				Env:        "test",
				DisavowURL: "https://disavow.com",
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			_cacheMock.
				EXPECT().
				GetJSON(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&domain.MFAMetadata{})).
				DoAndReturn(func(ctx context.Context, _ string, metadata *domain.MFAMetadata) error {
					metadata.UserID = uuid.New().String()
					metadata.PrivateKey = "private_key"
					return nil
				})

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.UserMFA{
					ID: uuid.New().String(),
					Metadata: &model.UserMFAMetaData{
						Email: "test@test.com",
					},
				}, nil)

			_cacheMock.
				EXPECT().
				SetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			emailService.
				EXPECT().
				SendEmail(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, nil, emailService, smsService)
		}(),
	})
}

func TestLoginController_VerifyLoginEmailCode(t *testing.T) {
	type testcase struct {
		name                        string
		err                         error
		ctx                         context.Context
		verifyLoginEmailCodeRequest *domain.VerifyLoginEmailCodeRequest
		loginController             ILoginController
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.VerifyLoginEmailCode(tc.ctx, tc.verifyLoginEmailCodeRequest)
			assert.Equal(t, tc.err, err)
		})
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		verifyLoginEmailCodeRequest: &domain.VerifyLoginEmailCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				Env: "test",
				RateLimit: &config.RateLimitConfig{
					LoginVerificationAttemptsThreshold:    5,
					LoginVerificationAttemptsLockDuration: time.Minute * 10,
				},
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			_cacheMock.
				EXPECT().
				GetJSON(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&domain.MFAMetadata{})).
				DoAndReturn(func(ctx context.Context, _ string, metadata *domain.MFAMetadata) error {
					metadata.UserID = uuid.New().String()
					metadata.PrivateKey = "private_key"
					metadata.Code = "123456"
					return nil
				})

			_cacheMock.
				EXPECT().
				Get(gomock.Any(), gomock.Any()).
				Return("1", nil)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(nil)

			_cacheMock.
				EXPECT().
				SetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, nil, emailService, smsService)
		}(),
	})
}

func TestLoginController_SendLoginPhoneCode(t *testing.T) {
	type testcase struct {
		name                      string
		err                       error
		ctx                       context.Context
		sendLoginPhoneCodeRequest *domain.SendLoginPhoneCodeRequest
		loginController           ILoginController
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.SendLoginPhoneCode(tc.ctx, tc.sendLoginPhoneCodeRequest)
			assert.Equal(t, tc.err, err)
		})
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		sendLoginPhoneCodeRequest: &domain.SendLoginPhoneCodeRequest{
			ReferenceID: uuid.New().String(),
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				Env: "test",
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			_cacheMock.
				EXPECT().
				GetJSON(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&domain.MFAMetadata{})).
				DoAndReturn(func(ctx context.Context, _ string, metadata *domain.MFAMetadata) error {
					metadata.UserID = uuid.New().String()
					metadata.PrivateKey = "private_key"
					return nil
				})

			userMFARepository.
				EXPECT().
				GetByUserIDAndMFAType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.UserMFA{
					ID: uuid.New().String(),
					Metadata: &model.UserMFAMetaData{
						Phone: "1234567890",
					},
				}, nil)

			_cacheMock.
				EXPECT().
				SetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			smsService.
				EXPECT().
				SendSMS(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, nil, emailService, smsService)
		}(),
	})
}

func TestLoginController_VerifyLoginPhoneCode(t *testing.T) {
	type testcase struct {
		name                        string
		err                         error
		ctx                         context.Context
		verifyLoginPhoneCodeRequest *domain.VerifyLoginPhoneCodeRequest
		loginController             ILoginController
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.loginController.VerifyLoginPhoneCode(tc.ctx, tc.verifyLoginPhoneCodeRequest)
			assert.Equal(t, tc.err, err)
		})
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyRequestID, uuid.New().String())

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		verifyLoginPhoneCodeRequest: &domain.VerifyLoginPhoneCodeRequest{
			ReferenceID: uuid.New().String(),
			Code:        "123456",
		},
		loginController: func() ILoginController {
			ctrl := gomock.NewController(t)
			cfg := &config.Config{
				Env: "test",
				RateLimit: &config.RateLimitConfig{
					LoginVerificationAttemptsThreshold:    5,
					LoginVerificationAttemptsLockDuration: time.Minute * 10,
				},
			}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
			emailService := emailMock.NewMockIEmail(ctrl)
			smsService := smsMock.NewMockISMS(ctrl)

			_cacheMock.
				EXPECT().
				GetJSON(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&domain.MFAMetadata{})).
				DoAndReturn(func(ctx context.Context, _ string, metadata *domain.MFAMetadata) error {
					metadata.UserID = uuid.New().String()
					metadata.PrivateKey = "private_key"
					metadata.Code = "123456"
					return nil
				})

			_cacheMock.
				EXPECT().
				Get(gomock.Any(), gomock.Any()).
				Return("1", nil)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(nil)

			_cacheMock.
				EXPECT().
				SetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, nil, emailService, smsService)
		}(),
	})
}
