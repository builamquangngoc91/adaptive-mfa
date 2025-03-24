package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type IUserVerificationController interface {
	SendEmailVerification(w http.ResponseWriter, r *http.Request)
	VerifyEmailVerification(w http.ResponseWriter, r *http.Request)
	SendPhoneVerification(w http.ResponseWriter, r *http.Request)
	VerifyPhoneVerification(w http.ResponseWriter, r *http.Request)
}

type UserVerificationController struct {
	cfg               *config.Config
	db                database.IDatabase
	cache             cache.ICache
	userRepository    repository.IUserRepository
	userMFARepository repository.IUserMFARepository
}

func NewUserVerificationController(
	cfg *config.Config,
	db database.IDatabase,
	cache cache.ICache,
	userRepository repository.IUserRepository,
	userMFARepository repository.IUserMFARepository,
) IUserVerificationController {
	return &UserVerificationController{
		cfg:               cfg,
		db:                db,
		cache:             cache,
		userRepository:    userRepository,
		userMFARepository: userMFARepository,
	}
}

func (h *UserVerificationController) SendEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	user, err := h.userRepository.GetByID(ctx, nil, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user.EmailVerifiedAt.Valid {
		http.Error(w, "Email already verified", http.StatusBadRequest)
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetEmailVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Email verification code: %s\n", code)

	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) VerifyEmailVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.VerifyEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID := ctx.Value(common.ContextKeyUserID).(string)
	code, err := h.cache.GetAndDel(ctx, cache.GetEmailVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.db.StartTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		user, err := h.userRepository.GetByID(ctx, tx, userID)
		if err != nil {
			return err
		}

		if code != request.Code || err == cache.Nil {
			return errors.New("invalid code")
		}

		if err := h.userRepository.UpdateEmailVerifiedAt(ctx, tx, userID); err != nil {
			return err
		}

		if err := h.userMFARepository.Create(ctx, tx, &model.UserMFA{
			ID:      uuid.New().String(),
			UserID:  userID,
			MFAType: model.UserMFATypeEmail,
			Metadata: &model.UserMFAMetaData{
				Email: user.Email.String,
			},
		}); err != nil {
			return err
		}

		return nil
	}, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Email verified")
	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) SendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	user, err := h.userRepository.GetByID(ctx, nil, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user.PhoneVerifiedAt.Valid {
		http.Error(w, "Phone already verified", http.StatusBadRequest)
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetPhoneVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Phone verification code: %s\n", code)
	w.WriteHeader(http.StatusOK)
}

func (h *UserVerificationController) VerifyPhoneVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.VerifyPhoneVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID := ctx.Value(common.ContextKeyUserID).(string)

	code, err := h.cache.GetAndDel(ctx, cache.GetPhoneVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.db.StartTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if code != request.Code || err == cache.Nil {
			return errors.New("invalid code")
		}

		user, err := h.userRepository.GetByID(ctx, tx, userID)
		if err != nil {
			return err
		}

		if err := h.userRepository.UpdatePhoneVerifiedAt(ctx, tx, userID); err != nil {
			return err
		}

		fmt.Println("Phone verified")

		if err := h.userMFARepository.Create(ctx, tx, &model.UserMFA{
			ID:      uuid.New().String(),
			UserID:  userID,
			MFAType: model.UserMFATypePhone,
			Metadata: &model.UserMFAMetaData{
				Phone: user.Phone.String,
			},
		}); err != nil {
			return err
		}

		return nil
	}, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Phone verified")
	w.WriteHeader(http.StatusOK)
}
