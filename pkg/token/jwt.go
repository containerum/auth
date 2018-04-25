package token

import (
	"time"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/pkg/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

type extendedClaims struct {
	jwt.StandardClaims
	ExtensionFields
	Kind Kind `json:"kind"`
}

// JWTIssuerValidatorConfig is config for JSON Web Tokens issuer and validator
type JWTIssuerValidatorConfig struct {
	SigningMethod        jwt.SigningMethod
	Issuer               string
	AccessTokenLifeTime  time.Duration
	RefreshTokenLifeTime time.Duration
	SigningKey           interface{}
	ValidationKey        interface{}
}

type jwtIssuerValidator struct {
	config JWTIssuerValidatorConfig
	logger *logrus.Entry
}

// NewJWTIssuerValidator sets up validator for self-contained JSON Web Tokens
func NewJWTIssuerValidator(config JWTIssuerValidatorConfig) IssuerValidator {
	logrus.WithField("config", config).Info("Initialized jwtIssuerValidator")
	jwt.TimeFunc = func() time.Time {
		return time.Now().UTC()
	}
	return &jwtIssuerValidator{
		config: config,
		logger: logrus.WithField("component", "jwtIssuerValidator"),
	}
}

func (j *jwtIssuerValidator) issueToken(id string, kind Kind, lifeTime time.Duration, extendedFields ExtensionFields) (token *IssuedToken, err error) {
	now := jwt.TimeFunc()
	claims := extendedClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        id,
			Issuer:    j.config.Issuer,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(lifeTime).Unix(),
		},
		ExtensionFields: extendedFields,
		Kind:            kind,
	}
	logCtx := logrus.Fields{
		"kind":     kind,
		"lifeTime": lifeTime,
		"id":       id,
		"claims":   claims,
	}
	j.logger.WithFields(logCtx).Debug("Issue token")
	value, err := jwt.NewWithClaims(j.config.SigningMethod, claims).SignedString(j.config.SigningKey)

	return &IssuedToken{
		Value:    value,
		ID:       id,
		IssuedAt: now,
		LifeTime: lifeTime,
	}, err
}

func (j *jwtIssuerValidator) IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error) {
	id := utils.NewUUID()
	refreshToken, err = j.issueToken(id, KindRefresh, j.config.RefreshTokenLifeTime, extensionFields)
	if err != nil {
		return
	}
	// do not include extension fields to access token
	accessToken, err = j.issueToken(id, KindAccess, j.config.AccessTokenLifeTime, ExtensionFields{})
	return
}

func (j *jwtIssuerValidator) ValidateToken(token string) (result *ValidationResult, err error) {
	j.logger.Debugf("Validating token %s", token)
	tokenObj, err := jwt.ParseWithClaims(token, new(extendedClaims), func(token *jwt.Token) (interface{}, error) {
		return j.config.ValidationKey, nil
	})
	if err != nil {
		return
	}

	validationResult := &ValidationResult{
		Valid: tokenObj.Valid,
		ID:    tokenObj.Claims.(*extendedClaims).Id,
		Kind:  tokenObj.Claims.(*extendedClaims).Kind,
	}
	j.logger.WithField("result", validationResult).Debugf("Validated token: %s", token)
	return validationResult, nil
}

func (j *jwtIssuerValidator) AccessFromRefresh(refreshToken string) (accessToken *IssuedToken, err error) {
	j.logger.Debugf("Reconstructing access token from refresh token %s", refreshToken)
	tokenObj, err := jwt.ParseWithClaims(refreshToken, new(extendedClaims), func(token *jwt.Token) (interface{}, error) {
		return j.config.ValidationKey, nil
	})
	if err != nil {
		return
	}

	claims := tokenObj.Claims.(*extendedClaims)

	if !tokenObj.Valid && claims.Kind != KindRefresh {
		return nil, autherr.ErrInvalidToken().AddDetails("invalid refresh token received")
	}

	if jwt.TimeFunc().After(time.Unix(claims.IssuedAt, 0).UTC().Add(j.config.AccessTokenLifeTime)) {
		return nil, autherr.ErrInvalidToken().AddDetails("access token will be invalid because it expired")
	}

	// access token differs from refresh token only in "ExpiresAt", "Kind" and "ExtensionFields" (it`s empty)
	claims.Kind = KindAccess
	// here we losing nanosecond precision
	claims.ExpiresAt = time.Unix(claims.IssuedAt, 0).Add(j.config.AccessTokenLifeTime).Unix()
	claims.ExtensionFields = ExtensionFields{}

	value, err := jwt.NewWithClaims(j.config.SigningMethod, claims).SignedString(j.config.SigningKey)
	return &IssuedToken{
		Value:    value,
		ID:       claims.Id,
		IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(),
		LifeTime: j.config.AccessTokenLifeTime,
	}, err
}

func (j *jwtIssuerValidator) Now() time.Time {
	return jwt.TimeFunc()
}
