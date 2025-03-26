package controller

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"adaptive-mfa/pkg/cache"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	"adaptive-mfa/pkg/common"
	appError "adaptive-mfa/pkg/error"
	repositoryMock "adaptive-mfa/repository/mock"

	"github.com/go-playground/assert/v2"
	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

func TestHackedController_Disavow(t *testing.T) {
	type testcase struct {
		name             string
		err              error
		ctx              context.Context
		hackedController IHackedController
	}

	refID := uuid.New().String()

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyParams, url.Values{
		"ref": {refID},
	})

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.hackedController.Disavow(tc.ctx)
			assert.Equal(t, tc.err, err)
		})
	}

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		hackedController: func() IHackedController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)

			_cacheMock.
				EXPECT().
				GetAndDelJSON(gomock.Any(), cache.GetMFAReferenceIDKey(refID), gomock.Any()).
				Return(nil)

			userLoginLogRepository.
				EXPECT().
				Create(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil)

			hackedController := NewHackedController(nil, _cacheMock, userLoginLogRepository)
			return hackedController
		}(),
	})

	validate(t, &testcase{
		name: "missing ref",
		ctx:  context.Background(),
		err:  appError.WithAppError(errors.New("reference ID is required"), appError.CodeBadRequest),
		hackedController: func() IHackedController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)

			hackedController := NewHackedController(nil, _cacheMock, userLoginLogRepository)
			return hackedController
		}(),
	})

	validate(t, &testcase{
		name: "invalid reference ID",
		ctx:  ctx,
		err:  appError.ErrorInvalidMFAReferenceID,
		hackedController: func() IHackedController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)
			userLoginLogRepository := repositoryMock.NewMockIUserLoginLogRepository(ctrl)

			_cacheMock.
				EXPECT().
				GetAndDelJSON(gomock.Any(), cache.GetMFAReferenceIDKey(refID), gomock.Any()).
				Return(appError.ErrorInvalidMFAReferenceID)

			hackedController := NewHackedController(nil, _cacheMock, userLoginLogRepository)
			return hackedController
		}(),
	})
}
