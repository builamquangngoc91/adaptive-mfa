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
