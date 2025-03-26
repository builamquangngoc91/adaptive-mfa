package controller

import (
	"adaptive-mfa/pkg/cache"
	cacheMock "adaptive-mfa/pkg/cache/mock"
	"adaptive-mfa/pkg/common"
	appError "adaptive-mfa/pkg/error"
	"context"
	"net/http"
	"testing"

	"github.com/go-playground/assert/v2"
	"go.uber.org/mock/gomock"
)

func TestLogoutController_Logout(t *testing.T) {
	type testcase struct {
		name             string
		err              error
		ctx              context.Context
		logoutController ILogoutController
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ContextKeyHeaders, http.Header{
		"Authorization": []string{"token"},
	})

	validate := func(t *testing.T, tc *testcase) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.logoutController.Logout(tc.ctx)
			assert.Equal(t, tc.err, err)
		})
	}

	validate(t, &testcase{
		name: "success",
		ctx:  ctx,
		err:  nil,
		logoutController: func() ILogoutController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(nil)

			logoutController := NewLogoutController(_cacheMock)
			return logoutController
		}(),
	})

	validate(t, &testcase{
		name: "missing token",
		ctx:  context.Background(),
		err:  appError.ErrorUnauthorized,
		logoutController: func() ILogoutController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)

			logoutController := NewLogoutController(_cacheMock)
			return logoutController
		}(),
	})

	validate(t, &testcase{
		name: "invalid token",
		ctx:  ctx,
		err:  appError.ErrorUnauthorized,
		logoutController: func() ILogoutController {
			ctrl := gomock.NewController(t)
			_cacheMock := cacheMock.NewMockICache(ctrl)

			_cacheMock.
				EXPECT().
				Del(gomock.Any(), gomock.Any()).
				Return(cache.Nil)

			logoutController := NewLogoutController(_cacheMock)
			return logoutController
		}(),
	})
}
