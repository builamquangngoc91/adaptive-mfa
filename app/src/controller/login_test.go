package controller

import (
	"context"
	"testing"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	emailMock "adaptive-mfa/pkg/email/mock"
	smsMock "adaptive-mfa/pkg/sms/mock"
	repositoryMock "adaptive-mfa/repository/mock"

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
			cfg := &config.Config{}
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userRepository := repositoryMock.NewMockIUserRepository(ctrl)
			userMFARepository := repositoryMock.NewMockIUserMFARepository(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)
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

			userLoginLogRepository.
				EXPECT().
				GetAnalysis(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.UserLoginLogAnalysis{
					CountDisavowedFromIP: database.NewNullInt64(0),
					LatestSuccess:        database.NewNullTime(time.Now()),
					CountAttempts:        database.NewNullInt64(0),
					CountAttemptsFromIP:  database.NewNullInt64(0),
				}, nil)

			_cacheMock.
				EXPECT().
				SetJSON(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewLoginController(cfg, _cacheMock, userRepository, userMFARepository, userLoginLogRepository, emailService, smsService)
		}(),
	})
}
