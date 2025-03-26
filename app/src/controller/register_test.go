package controller

import (
	"context"
	"errors"
	"testing"

	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	appError "adaptive-mfa/pkg/error"
	repositoryMock "adaptive-mfa/repository/mock"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

func TestRegisterController_Register(t *testing.T) {
	type testcase struct {
		name       string
		ctx        context.Context
		req        *domain.RegisterRequest
		controller IRegisterController
		err        error
	}

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.controller.Register(tc.ctx, tc.req)
			assert.Equal(t, tc.err, err)
		})
	}

	validate(t, &testcase{
		name: "error: username is required",
		ctx:  context.Background(),
		req:  &domain.RegisterRequest{},
		err:  appError.WithAppError(errors.New("username is required"), appError.CodeBadRequest),
		controller: func() IRegisterController {
			ctrl := gomock.NewController(t)
			cacheMock := cacheMock.NewMockICache(ctrl)
			userRepositoryMock := repositoryMock.NewMockIUserRepository(ctrl)

			return NewRegisterController(cacheMock, userRepositoryMock)
		}(),
	})

	validate(t, &testcase{
		name: "error: password is required",
		ctx:  context.Background(),
		req: &domain.RegisterRequest{
			Username: "test",
		},
		err: appError.WithAppError(errors.New("password is required"), appError.CodeBadRequest),
		controller: func() IRegisterController {
			ctrl := gomock.NewController(t)
			cacheMock := cacheMock.NewMockICache(ctrl)
			userRepositoryMock := repositoryMock.NewMockIUserRepository(ctrl)

			return NewRegisterController(cacheMock, userRepositoryMock)
		}(),
	})

	validate(t, &testcase{
		name: "error: fullname is required",
		ctx:  context.Background(),
		req: &domain.RegisterRequest{
			Username: "test",
			Password: "password",
		},
		err: appError.WithAppError(errors.New("fullname is required"), appError.CodeBadRequest),
		controller: func() IRegisterController {
			ctrl := gomock.NewController(t)
			cacheMock := cacheMock.NewMockICache(ctrl)
			userRepositoryMock := repositoryMock.NewMockIUserRepository(ctrl)

			return NewRegisterController(cacheMock, userRepositoryMock)
		}(),
	})

	validate(t, &testcase{
		name: "error: username already exists",
		ctx:  context.Background(),
		req: &domain.RegisterRequest{
			Username: "test",
			Password: "password",
			Fullname: "test",
		},
		err: appError.WithAppError(errors.New("username already exists"), appError.CodeBadRequest),
		controller: func() IRegisterController {
			ctrl := gomock.NewController(t)
			cacheMock := cacheMock.NewMockICache(ctrl)
			userRepositoryMock := repositoryMock.NewMockIUserRepository(ctrl)

			userRepositoryMock.
				EXPECT().
				GetByUsername(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.User{
					ID:       uuid.New().String(),
					Username: "test",
					Fullname: "test",
				}, nil)

			return NewRegisterController(cacheMock, userRepositoryMock)
		}(),
	})

	validate(t, &testcase{
		name: "success",
		ctx:  context.Background(),
		req: &domain.RegisterRequest{
			Username: "test",
			Password: "password",
			Fullname: "test",
		},
		err: nil,
		controller: func() IRegisterController {
			ctrl := gomock.NewController(t)
			cacheMock := cacheMock.NewMockICache(ctrl)
			userRepositoryMock := repositoryMock.NewMockIUserRepository(ctrl)

			userRepositoryMock.
				EXPECT().
				GetByUsername(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, nil)

			userRepositoryMock.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			return NewRegisterController(cacheMock, userRepositoryMock)
		}(),
	})
}
