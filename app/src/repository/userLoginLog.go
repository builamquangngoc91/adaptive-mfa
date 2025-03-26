package repository

import (
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/database"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

//go:generate mockgen -source=userLoginLog.go -destination=./mock/userLoginLog.go -package=mock
type IUserLoginLogRepository interface {
	Create(ctx context.Context, tx *sql.Tx, userLoginLog *model.UserLoginLog) error
	GetAnalysis(ctx context.Context, tx *sql.Tx, userID, ipAddress string) (*model.UserLoginLogAnalysis, error)
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
			ip_address, 
			user_agent, 
			device_id, 
			metadata, 
			login_type, 
			login_status,
			attempts,
			required_mfa,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
	`
	result, err := r.db.ExecTx(ctx, tx, command,
		userLoginLog.ID,
		userLoginLog.RequestID,
		userLoginLog.ReferenceID,
		userLoginLog.UserID,
		userLoginLog.IPAddress,
		userLoginLog.UserAgent,
		userLoginLog.DeviceID,
		userLoginLog.Metadata,
		userLoginLog.LoginType,
		userLoginLog.LoginStatus,
		userLoginLog.Attempts,
		userLoginLog.RequiredMFA,
	)
	if err != nil {
		fmt.Println(err)
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

func (r *UserLoginLogRepository) GetAnalysis(ctx context.Context, tx *sql.Tx, userID, ipAddress string) (*model.UserLoginLogAnalysis, error) {
	query := `
		WITH latest_success_from_ip AS (
			SELECT ull.created_at
			FROM user_login_logs ull 
			WHERE ull.user_id = $1
				AND ull.ip_address = $2
				AND ull.login_status = 'success'
				AND NOT (ull.login_type = 'basic_auth' AND ull.required_mfa IS TRUE)
			ORDER BY created_at DESC
			LIMIT 1
		),
		latest_success AS (
			SELECT created_at
			FROM user_login_logs ull 
			WHERE ull.user_id = $1
				AND ull.login_status = 'success'
				AND NOT (ull.login_type = 'basic_auth' AND ull.required_mfa IS TRUE)
			ORDER BY created_at DESC
			LIMIT 1
		),
		count_attempts_from_ip AS (
			SELECT count(ull.id) AS attempt_count
			FROM user_login_logs ull 
			WHERE ull.user_id = $1
				AND ull.ip_address = $2
				AND ull.login_status = 'fail'
				AND ull.created_at > (SELECT created_at FROM latest_success_from_ip)
		),
		count_attempts AS (
			SELECT count(ull.id) AS attempt_count
			FROM user_login_logs ull 
			WHERE ull.user_id = $1
				AND ull.login_status = 'fail'
				AND ull.created_at > (SELECT created_at FROM latest_success)
		),
		count_disavowed_from_ip AS (
			SELECT count(ull.id) AS disavowed_count
			FROM user_login_logs ull 
			WHERE ull.user_id = $1
				AND ull.ip_address = $2
				AND ull.login_status = 'disavowed'
				AND ull.created_at > (SELECT created_at FROM latest_success_from_ip)
		)
		SELECT
			(SELECT created_at FROM latest_success_from_ip) AS latest_success_from_ip,
			(SELECT created_at FROM latest_success) AS latest_success,
			(SELECT attempt_count FROM count_attempts_from_ip) AS count_attempts_from_ip,
			(SELECT attempt_count FROM count_attempts) AS count_attempts,
			(SELECT disavowed_count FROM count_disavowed_from_ip) AS count_disavowed_from_ip
	`
	var userLoginLogAnalysis model.UserLoginLogAnalysis
	if err := r.db.QueryRowTx(ctx, tx, query, userID, ipAddress).
		Scan(
			&userLoginLogAnalysis.LatestSuccessFromIP,
			&userLoginLogAnalysis.LatestSuccess,
			&userLoginLogAnalysis.CountAttemptsFromIP,
			&userLoginLogAnalysis.CountAttempts,
			&userLoginLogAnalysis.CountDisavowedFromIP,
		); err != nil {
		return nil, err
	}

	return &userLoginLogAnalysis, nil
}
