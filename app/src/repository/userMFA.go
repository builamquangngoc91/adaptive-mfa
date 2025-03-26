package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"adaptive-mfa/model"
	"adaptive-mfa/pkg/database"
)

//go:generate mockgen -source=userMfa.go -destination=./mock/userMfa.go -package=mock
type IUserMFARepository interface {
	Create(ctx context.Context, tx *sql.Tx, userMFA *model.UserMFA) error
	ListByUserID(ctx context.Context, tx *sql.Tx, userID string) ([]*model.UserMFA, error)
	GetByUserIDAndMFAType(ctx context.Context, tx *sql.Tx, userID string, mfaType string) (*model.UserMFA, error)
	SoftDelete(ctx context.Context, tx *sql.Tx, id string) error
}

type UserMFARepository struct {
	db database.IDatabase
}

func NewUserMFARepository(db database.IDatabase) IUserMFARepository {
	return &UserMFARepository{db: db}
}

func (r *UserMFARepository) Create(ctx context.Context, tx *sql.Tx, userMFA *model.UserMFA) error {
	command := `
	INSERT INTO user_mfas (id, user_id, mfa_type, metadata, created_at)
	VALUES ($1, $2, $3, $4, NOW())`
	result, err := r.db.ExecTx(ctx, tx, command, userMFA.ID, userMFA.UserID, userMFA.MFAType, userMFA.Metadata)
	if err != nil {
		return fmt.Errorf("failed to create user_mfa: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to create user_mfa")
	}

	return nil
}

func (r *UserMFARepository) ListByUserID(ctx context.Context, tx *sql.Tx, userID string) ([]*model.UserMFA, error) {
	query := `
		SELECT id, user_id, mfa_type, metadata, created_at, updated_at, deleted_at 
		FROM user_mfas 
		WHERE user_id = $1 
		AND deleted_at IS NULL`

	rows, err := r.db.QueryTx(ctx, tx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user_mfas: %w", err)
	}

	userMFAs := make([]*model.UserMFA, 0)
	for rows.Next() {
		var userMFA model.UserMFA
		if err := rows.Scan(&userMFA.ID, &userMFA.UserID, &userMFA.MFAType, &userMFA.Metadata, &userMFA.CreatedAt, &userMFA.UpdatedAt, &userMFA.DeletedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user_mfa: %w", err)
		}

		userMFAs = append(userMFAs, &userMFA)
	}

	return userMFAs, nil
}

func (r *UserMFARepository) GetByUserIDAndMFAType(ctx context.Context, tx *sql.Tx, userID string, mfaType string) (*model.UserMFA, error) {
	query := `
		SELECT id, user_id, mfa_type, metadata, created_at, updated_at, deleted_at 
		FROM user_mfas 
		WHERE user_id = $1 
		AND mfa_type = $2 
		AND deleted_at IS NULL`

	var userMFA model.UserMFA
	if err := r.db.QueryRowTx(ctx, tx, query, userID, mfaType).
		Scan(&userMFA.ID, &userMFA.UserID, &userMFA.MFAType, &userMFA.Metadata, &userMFA.CreatedAt, &userMFA.UpdatedAt, &userMFA.DeletedAt); err != nil {
		return nil, err
	}

	return &userMFA, nil
}

func (r *UserMFARepository) SoftDelete(ctx context.Context, tx *sql.Tx, id string) error {
	command := `
	UPDATE user_mfas 
	SET deleted_at = NOW()
	WHERE id = $1`
	result, err := r.db.ExecTx(ctx, tx, command, id)
	if err != nil {
		return fmt.Errorf("failed to soft delete user_mfa: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to soft delete user_mfa")
	}

	return nil
}
