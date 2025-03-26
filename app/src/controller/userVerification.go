package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/email"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/pkg/sms"
	"adaptive-mfa/repository"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
)

//go:generate mockgen -source=userVerification.go -destination=./mock/userVerification.go -package=mock
type IUserVerificationController interface {
	SendEmailVerification(ctx context.Context, req *domain.SendEmailVerificationRequest) (*domain.SendEmailVerificationResponse, error)
	VerifyEmailVerification(ctx context.Context, req *domain.VerifyEmailVerificationRequest) (*domain.VerifyEmailVerificationResponse, error)
	SendPhoneVerification(ctx context.Context, req *domain.SendPhoneVerificationRequest) (*domain.SendPhoneVerificationResponse, error)
	VerifyPhoneVerification(ctx context.Context, req *domain.VerifyPhoneVerificationRequest) (*domain.VerifyPhoneVerificationResponse, error)
}

type UserVerificationController struct {
	cfg               *config.Config
	db                database.IDatabase
	cache             cache.ICache
	userRepository    repository.IUserRepository
	userMFARepository repository.IUserMFARepository
	emailService      email.IEmail
	smsService        sms.ISMS
}

func NewUserVerificationController(
	cfg *config.Config,
	db database.IDatabase,
	cache cache.ICache,
	userRepository repository.IUserRepository,
	userMFARepository repository.IUserMFARepository,
	emailService email.IEmail,
	smsService sms.ISMS,
) IUserVerificationController {
	return &UserVerificationController{
		cfg:               cfg,
		db:                db,
		cache:             cache,
		userRepository:    userRepository,
		userMFARepository: userMFARepository,
		emailService:      emailService,
		smsService:        smsService,
	}
}

func (h *UserVerificationController) SendEmailVerification(ctx context.Context, req *domain.SendEmailVerificationRequest) (*domain.SendEmailVerificationResponse, error) {
	userID := common.GetUserID(ctx)

	user, err := h.userRepository.GetByID(ctx, nil, userID)
	if err != nil {
		return nil, err
	}

	if user.EmailVerifiedAt.Valid {
		return nil, errors.New("email already verified")
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetEmailVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5), false); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("Your email verification code is %s", code)
	h.emailService.SendEmail(ctx, user.Email.String, "Email Verification", msg)
	return &domain.SendEmailVerificationResponse{}, nil
}

func (h *UserVerificationController) VerifyEmailVerification(ctx context.Context, req *domain.VerifyEmailVerificationRequest) (*domain.VerifyEmailVerificationResponse, error) {
	userID := common.GetUserID(ctx)
	code, err := h.cache.GetAndDel(ctx, cache.GetEmailVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		return nil, err
	}

	err = h.db.StartTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		user, err := h.userRepository.GetByID(ctx, tx, userID)
		if err != nil {
			return err
		}

		if code != req.Code || err == cache.Nil {
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
		return nil, err
	}

	return &domain.VerifyEmailVerificationResponse{}, nil
}

func (h *UserVerificationController) SendPhoneVerification(ctx context.Context, req *domain.SendPhoneVerificationRequest) (*domain.SendPhoneVerificationResponse, error) {
	userID := common.GetUserID(ctx)

	user, err := h.userRepository.GetByID(ctx, nil, userID)
	if err != nil {
		return nil, err
	}

	if user.PhoneVerifiedAt.Valid {
		return nil, errors.New("phone already verified")
	}

	code := fmt.Sprintf("%06d", rand.Intn(999999))
	if err := h.cache.Set(ctx, cache.GetPhoneVerificationCodeKey(userID), code, ptr.ToPtr(time.Minute*5), false); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("Your phone verification code is %s", code)
	h.smsService.SendSMS(ctx, user.Phone.String, msg)
	return &domain.SendPhoneVerificationResponse{}, nil
}

func (h *UserVerificationController) VerifyPhoneVerification(ctx context.Context, req *domain.VerifyPhoneVerificationRequest) (*domain.VerifyPhoneVerificationResponse, error) {
	userID := common.GetUserID(ctx)

	code, err := h.cache.GetAndDel(ctx, cache.GetPhoneVerificationCodeKey(userID))
	if err != nil && err != cache.Nil {
		return nil, err
	}

	err = h.db.StartTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if code != req.Code || err == cache.Nil {
			return errors.New("invalid code")
		}

		user, err := h.userRepository.GetByID(ctx, tx, userID)
		if err != nil {
			return err
		}

		if err := h.userRepository.UpdatePhoneVerifiedAt(ctx, tx, userID); err != nil {
			return err
		}

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
		return nil, err
	}

	return &domain.VerifyPhoneVerificationResponse{}, nil
}
