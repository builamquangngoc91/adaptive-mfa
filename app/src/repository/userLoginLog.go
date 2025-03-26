package repository

import (
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/database"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type IUserLoginLogRepository interface {
	Create(ctx context.Context, tx *sql.Tx, userLoginLog *model.UserLoginLog) error
}

type UserLoginLogRepository struct {
	db database.IDatabase
}

func NewUserLoginLogRepository(db database.IDatabase) IUserLoginLogRepository {
	return &UserLoginLogRepository{db: db}
}

func (r *UserLoginLogRepository) Create(ctx context.Context, tx *sql.Tx, userLoginLog *model.UserLoginLog) error {
	command := `
		INSERT INTO user_login_logs (
			id, 
			request_id, 
			reference_id, 
			user_id, 
			username, 
			ip_address, 
			user_agent, 
			device_id, 
			metadata, 
			login_type, 
			login_status,
			is_impersonation,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	result, err := r.db.ExecTx(ctx, tx, command,
		userLoginLog.ID,
		userLoginLog.RequestID,
		userLoginLog.ReferenceID,
		userLoginLog.UserID,
		userLoginLog.Username,
		userLoginLog.IPAddress,
		userLoginLog.UserAgent,
		userLoginLog.DeviceID,
		userLoginLog.Metadata,
		userLoginLog.LoginType,
		userLoginLog.LoginStatus,
		userLoginLog.IsImpersonation,
		userLoginLog.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user login log: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to create user login log")
	}
	return nil
}
