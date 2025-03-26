// Code generated by MockGen. DO NOT EDIT.
// Source: logout.go
//
// Generated by this command:
//
//	mockgen -source=logout.go -destination=./mock/logout.go -package=mock
//
// Package mock is a generated GoMock package.
package mock

import (
	domain "adaptive-mfa/domain"
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockILogoutController is a mock of ILogoutController interface.
type MockILogoutController struct {
	ctrl     *gomock.Controller
	recorder *MockILogoutControllerMockRecorder
}

// MockILogoutControllerMockRecorder is the mock recorder for MockILogoutController.
type MockILogoutControllerMockRecorder struct {
	mock *MockILogoutController
}

// NewMockILogoutController creates a new mock instance.
func NewMockILogoutController(ctrl *gomock.Controller) *MockILogoutController {
	mock := &MockILogoutController{ctrl: ctrl}
	mock.recorder = &MockILogoutControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockILogoutController) EXPECT() *MockILogoutControllerMockRecorder {
	return m.recorder
}

// Logout mocks base method.
func (m *MockILogoutController) Logout(arg0 context.Context, arg1 *domain.LogoutRequest) (*domain.LogoutResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logout", arg0, arg1)
	ret0, _ := ret[0].(*domain.LogoutResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Logout indicates an expected call of Logout.
func (mr *MockILogoutControllerMockRecorder) Logout(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logout", reflect.TypeOf((*MockILogoutController)(nil).Logout), arg0, arg1)
}
