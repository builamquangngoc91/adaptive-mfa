// Code generated by MockGen. DO NOT EDIT.
// Source: user.go
//
// Generated by this command:
//
//	mockgen -source=user.go -destination=./mock/user.go -package=mock
//
// Package mock is a generated GoMock package.
package mock

import (
	model "adaptive-mfa/model"
	context "context"
	sql "database/sql"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockIUserRepository is a mock of IUserRepository interface.
type MockIUserRepository struct {
	ctrl     *gomock.Controller
	recorder *MockIUserRepositoryMockRecorder
}

// MockIUserRepositoryMockRecorder is the mock recorder for MockIUserRepository.
type MockIUserRepositoryMockRecorder struct {
	mock *MockIUserRepository
}

// NewMockIUserRepository creates a new mock instance.
func NewMockIUserRepository(ctrl *gomock.Controller) *MockIUserRepository {
	mock := &MockIUserRepository{ctrl: ctrl}
	mock.recorder = &MockIUserRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIUserRepository) EXPECT() *MockIUserRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockIUserRepository) Create(arg0 context.Context, arg1 *sql.Tx, arg2 *model.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockIUserRepositoryMockRecorder) Create(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockIUserRepository)(nil).Create), arg0, arg1, arg2)
}

// GetByID mocks base method.
func (m *MockIUserRepository) GetByID(arg0 context.Context, arg1 *sql.Tx, arg2 string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", arg0, arg1, arg2)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockIUserRepositoryMockRecorder) GetByID(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockIUserRepository)(nil).GetByID), arg0, arg1, arg2)
}

// GetByUsername mocks base method.
func (m *MockIUserRepository) GetByUsername(arg0 context.Context, arg1 *sql.Tx, arg2 string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByUsername", arg0, arg1, arg2)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByUsername indicates an expected call of GetByUsername.
func (mr *MockIUserRepositoryMockRecorder) GetByUsername(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByUsername", reflect.TypeOf((*MockIUserRepository)(nil).GetByUsername), arg0, arg1, arg2)
}

// UpdateEmailVerifiedAt mocks base method.
func (m *MockIUserRepository) UpdateEmailVerifiedAt(arg0 context.Context, arg1 *sql.Tx, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateEmailVerifiedAt", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateEmailVerifiedAt indicates an expected call of UpdateEmailVerifiedAt.
func (mr *MockIUserRepositoryMockRecorder) UpdateEmailVerifiedAt(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateEmailVerifiedAt", reflect.TypeOf((*MockIUserRepository)(nil).UpdateEmailVerifiedAt), arg0, arg1, arg2)
}

// UpdatePhoneVerifiedAt mocks base method.
func (m *MockIUserRepository) UpdatePhoneVerifiedAt(arg0 context.Context, arg1 *sql.Tx, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdatePhoneVerifiedAt", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdatePhoneVerifiedAt indicates an expected call of UpdatePhoneVerifiedAt.
func (mr *MockIUserRepositoryMockRecorder) UpdatePhoneVerifiedAt(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePhoneVerifiedAt", reflect.TypeOf((*MockIUserRepository)(nil).UpdatePhoneVerifiedAt), arg0, arg1, arg2)
}
