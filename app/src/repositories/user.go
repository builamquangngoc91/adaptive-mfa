package repositories

import (
	"adaptive-mfa/models"
	"adaptive-mfa/pkg/database"
	"context"
	"errors"
	"fmt"
)

type IUserRepository interface {
	Create(context.Context, *models.User) error
	GetByUsername(context.Context, string) (*models.User, error)
	GetByID(context.Context, string) (*models.User, error)
	UpdateEmailVerifiedAt(context.Context, string) error
	UpdatePhoneVerifiedAt(context.Context, string) error
}

type UserRepository struct {
	db database.IDatabase
}

func NewUserRepository(db database.IDatabase) IUserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	command := `
		INSERT INTO users (id, fullname, username, email, phone, hash_password, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())`
	result, err := r.db.Exec(ctx, command, user.ID, user.Fullname, user.Username, user.Email, user.Phone, user.HashPassword)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to create user")
	}

	return nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, phone, hash_password, email_verified_at, phone_verified_at, created_at, updated_at, deleted_at 
		FROM users 
		WHERE username = $1 AND deleted_at IS NULL`

	var user models.User
	if err := r.db.QueryRow(ctx, query, username).Scan(&user.ID, &user.Username, &user.Email, &user.Phone, &user.HashPassword, &user.EmailVerifiedAt, &user.PhoneVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, username, email, phone, hash_password, email_verified_at, phone_verified_at, created_at, updated_at, deleted_at 
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	var user models.User
	if err := r.db.QueryRow(ctx, query, id).Scan(&user.ID, &user.Username, &user.Email, &user.Phone, &user.HashPassword, &user.EmailVerifiedAt, &user.PhoneVerifiedAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) UpdateEmailVerifiedAt(ctx context.Context, id string) error {
	command := `
		UPDATE users 
		SET email_verified_at = NOW(),
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, command, id)
	if err != nil {
		return fmt.Errorf("failed to update email verified at: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to update email verified at")
	}

	return nil
}

func (r *UserRepository) UpdatePhoneVerifiedAt(ctx context.Context, id string) error {
	command := `
		UPDATE users 
		SET phone_verified_at = NOW(),
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, command, id)
	if err != nil {
		return fmt.Errorf("failed to update phone verified at: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("failed to update phone verified at")
	}

	return nil
}
