// Code generated by MockGen. DO NOT EDIT.
// Source: ./internal/service/crypto/base.go
//
// Generated by this command:
//
//	mockgen -source=./internal/service/crypto/base.go -destination=tests/mocks/./service/crypto/base.go
//

// Package mock_crypto is a generated GoMock package.
package mock_crypto

import (
	context "context"
	reflect "reflect"

	pgx "github.com/jackc/pgx/v5"
	gomock "go.uber.org/mock/gomock"

	postgresql "github.com/agungcandra/snap/internal/repository/postgresql"
)

// MockrepositoryWithoutTx is a mock of repositoryWithoutTx interface.
type MockrepositoryWithoutTx struct {
	ctrl     *gomock.Controller
	recorder *MockrepositoryWithoutTxMockRecorder
}

// MockrepositoryWithoutTxMockRecorder is the mock recorder for MockrepositoryWithoutTx.
type MockrepositoryWithoutTxMockRecorder struct {
	mock *MockrepositoryWithoutTx
}

// NewMockrepositoryWithoutTx creates a new mock instance.
func NewMockrepositoryWithoutTx(ctrl *gomock.Controller) *MockrepositoryWithoutTx {
	mock := &MockrepositoryWithoutTx{ctrl: ctrl}
	mock.recorder = &MockrepositoryWithoutTxMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockrepositoryWithoutTx) EXPECT() *MockrepositoryWithoutTxMockRecorder {
	return m.recorder
}

// InsertKey mocks base method.
func (m *MockrepositoryWithoutTx) InsertKey(ctx context.Context, arg postgresql.InsertKeyParams) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertKey", ctx, arg)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertKey indicates an expected call of InsertKey.
func (mr *MockrepositoryWithoutTxMockRecorder) InsertKey(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertKey", reflect.TypeOf((*MockrepositoryWithoutTx)(nil).InsertKey), ctx, arg)
}

// InsertNonce mocks base method.
func (m *MockrepositoryWithoutTx) InsertNonce(ctx context.Context, arg postgresql.InsertNonceParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertNonce", ctx, arg)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertNonce indicates an expected call of InsertNonce.
func (mr *MockrepositoryWithoutTxMockRecorder) InsertNonce(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertNonce", reflect.TypeOf((*MockrepositoryWithoutTx)(nil).InsertNonce), ctx, arg)
}

// InsertSalt mocks base method.
func (m *MockrepositoryWithoutTx) InsertSalt(ctx context.Context, arg postgresql.InsertSaltParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertSalt", ctx, arg)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertSalt indicates an expected call of InsertSalt.
func (mr *MockrepositoryWithoutTxMockRecorder) InsertSalt(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertSalt", reflect.TypeOf((*MockrepositoryWithoutTx)(nil).InsertSalt), ctx, arg)
}

// Mockrepository is a mock of repository interface.
type Mockrepository struct {
	ctrl     *gomock.Controller
	recorder *MockrepositoryMockRecorder
}

// MockrepositoryMockRecorder is the mock recorder for Mockrepository.
type MockrepositoryMockRecorder struct {
	mock *Mockrepository
}

// NewMockrepository creates a new mock instance.
func NewMockrepository(ctrl *gomock.Controller) *Mockrepository {
	mock := &Mockrepository{ctrl: ctrl}
	mock.recorder = &MockrepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockrepository) EXPECT() *MockrepositoryMockRecorder {
	return m.recorder
}

// InsertKey mocks base method.
func (m *Mockrepository) InsertKey(ctx context.Context, arg postgresql.InsertKeyParams) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertKey", ctx, arg)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertKey indicates an expected call of InsertKey.
func (mr *MockrepositoryMockRecorder) InsertKey(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertKey", reflect.TypeOf((*Mockrepository)(nil).InsertKey), ctx, arg)
}

// InsertNonce mocks base method.
func (m *Mockrepository) InsertNonce(ctx context.Context, arg postgresql.InsertNonceParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertNonce", ctx, arg)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertNonce indicates an expected call of InsertNonce.
func (mr *MockrepositoryMockRecorder) InsertNonce(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertNonce", reflect.TypeOf((*Mockrepository)(nil).InsertNonce), ctx, arg)
}

// InsertSalt mocks base method.
func (m *Mockrepository) InsertSalt(ctx context.Context, arg postgresql.InsertSaltParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertSalt", ctx, arg)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertSalt indicates an expected call of InsertSalt.
func (mr *MockrepositoryMockRecorder) InsertSalt(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertSalt", reflect.TypeOf((*Mockrepository)(nil).InsertSalt), ctx, arg)
}

// WithTx mocks base method.
func (m *Mockrepository) WithTx(tx pgx.Tx) *postgresql.Queries {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithTx", tx)
	ret0, _ := ret[0].(*postgresql.Queries)
	return ret0
}

// WithTx indicates an expected call of WithTx.
func (mr *MockrepositoryMockRecorder) WithTx(tx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithTx", reflect.TypeOf((*Mockrepository)(nil).WithTx), tx)
}