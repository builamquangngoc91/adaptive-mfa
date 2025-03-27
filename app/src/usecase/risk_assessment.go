package usecase

import (
	"context"
	"errors"
	"time"

	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/repository"
)

type RiskAssessmentLevel int

const (
	RiskAssessmentLevelLow RiskAssessmentLevel = iota
	RiskAssessmentLevelMedium
	RiskAssessmentLevelHigh
)

//go:generate mockgen -source=risk_assessment.go -destination=mock/risk_assessment.go -package=mock
type IRiskAssessmentUsecase interface {
	CalculateScore(ctx context.Context, arg interface{}) (RiskAssessmentLevel, error)
}

type RiskAssessmentUsecase struct {
	userMFARepository      repository.IUserMFARepository
	userLoginLogRepository repository.IUserLoginLogRepository
}

func NewRiskAssessmentUsecase(userMFARepository repository.IUserMFARepository, userLoginLogRepository repository.IUserLoginLogRepository) IRiskAssessmentUsecase {
	return &RiskAssessmentUsecase{
		userMFARepository:      userMFARepository,
		userLoginLogRepository: userLoginLogRepository,
	}
}

type CalculateScoreArg struct {
	UserID    string
	IPAddress string
}

func (u *RiskAssessmentUsecase) CalculateScore(ctx context.Context, arg interface{}) (RiskAssessmentLevel, error) {
	calculateScoreArg, ok := arg.(CalculateScoreArg)
	if !ok {
		return RiskAssessmentLevelLow, appError.WithAppError(errors.New("invalid argument"), appError.CodeInternalServerError)
	}

	userMFAs, err := u.userMFARepository.ListByUserID(ctx, nil, calculateScoreArg.UserID)
	if err != nil {
		return RiskAssessmentLevelLow, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if len(userMFAs) == 0 {
		return RiskAssessmentLevelLow, nil
	}

	analysis, err := u.userLoginLogRepository.GetAnalysis(ctx, nil, calculateScoreArg.UserID, calculateScoreArg.IPAddress)
	if err != nil {
		return RiskAssessmentLevelLow, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	if !analysis.CountDisavowedFromIP.Valid || analysis.CountDisavowedFromIP.Int64 > 0 {
		return RiskAssessmentLevelHigh, nil
	}

	if !analysis.LatestSuccess.Valid {
		return RiskAssessmentLevelLow, nil
	}

	if analysis.CountAttemptsFromIP.Int64 >= 5 {
		return RiskAssessmentLevelHigh, nil
	}

	if analysis.CountAttempts.Int64 >= 10 {
		return RiskAssessmentLevelHigh, nil
	}

	if !analysis.LatestSuccessFromIP.Valid || analysis.LatestSuccessFromIP.Time.After(time.Now().Add(time.Hour*24)) {
		return RiskAssessmentLevelHigh, nil
	}

	return RiskAssessmentLevelLow, nil
}
