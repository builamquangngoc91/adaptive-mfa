package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/thanhpk/randstr"
)

type ITOTPController interface {
	AddTOTPMethod(w http.ResponseWriter, r *http.Request)
	DeleteTOTPMethod(w http.ResponseWriter, r *http.Request)
	VerifyTOTPCode(w http.ResponseWriter, r *http.Request)
	ListTOTPMethods(w http.ResponseWriter, r *http.Request)
}

type TOTPController struct {
	db                database.IDatabase
	cache             cache.ICache
	userMFARepository repository.IUserMFARepository
}

func NewTOTPController(db database.IDatabase, userMFARepository repository.IUserMFARepository, cache cache.ICache) *TOTPController {
	return &TOTPController{
		db:                db,
		cache:             cache,
		userMFARepository: userMFARepository,
	}
}

func (c *TOTPController) AddTOTPMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	existingUserMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if existingUserMFA != nil {
		http.Error(w, "TOTP method already exists", http.StatusBadRequest)
		return
	}

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Adaptive MFA",
		AccountName: userID,
		SecretSize:  12,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := c.userMFARepository.Create(ctx, nil, &model.UserMFA{
		ID:      uuid.New().String(),
		UserID:  userID,
		MFAType: model.UserMFATypeOTP,
		Metadata: &model.UserMFAMetaData{
			Secret: totpKey.Secret(),
		},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := domain.AddTOTPMethodResponse{
		Secret: totpKey.Secret(),
		Issuer: "Adaptive MFA",
	}

	json.NewEncoder(w).Encode(response)
	w.WriteHeader(http.StatusOK)

}

func (c *TOTPController) DeleteTOTPMethod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, userID, string(model.UserMFATypeOTP))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userMFA == nil {
		http.Error(w, "TOTP method not found", http.StatusBadRequest)
		return
	}

	if err := c.userMFARepository.SoftDelete(ctx, nil, userMFA.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (c *TOTPController) VerifyTOTPCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var request domain.VerifyTOTPCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mfaMetadata domain.MFAMetadata
	if err := c.cache.GetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), &mfaMetadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userMFA, err := c.userMFARepository.GetByUserIDAndMFAType(ctx, nil, mfaMetadata.UserID, string(model.UserMFATypeOTP))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userMFA == nil {
		http.Error(w, "TOTP method not found", http.StatusBadRequest)
		return
	}

	valid := totp.Validate(request.Code, userMFA.Metadata.Secret)
	if !valid {
		http.Error(w, "Invalid TOTP code", http.StatusBadRequest)
		return
	}

	mfaMetadata.PrivateKey = randstr.Hex(16)

	if err := c.cache.SetJSON(ctx, cache.GetMFAReferenceIDKey(request.ReferenceID), mfaMetadata, ptr.ToPtr(time.Minute*5)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := domain.VerifyTOTPCodeResponse{
		ReferenceID: request.ReferenceID,
		PrivateKey:  mfaMetadata.PrivateKey,
	}

	json.NewEncoder(w).Encode(response)
	w.WriteHeader(http.StatusOK)
}

func (c *TOTPController) ListTOTPMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(common.ContextKeyUserID).(string)

	userMFAs, err := c.userMFARepository.ListByUserID(ctx, nil, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	methods := make([]string, len(userMFAs))
	for i, userMFA := range userMFAs {
		methods[i] = string(userMFA.MFAType)
	}

	response := domain.ListTOTPMethodsResponse{
		Methods: methods,
	}

	json.NewEncoder(w).Encode(response)
	w.WriteHeader(http.StatusOK)
}
