package token

import (
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/dgrijalva/jwt-go"
	"bitbucket.org/exonch/ch-auth/utils"
)

// compile-time assertion to check if our type implements IssuerValidator interface
var _ IssuerValidator = &JWTIssuerValidator{}

type extendedClaims struct {
	jwt.StandardClaims
	ExtensionFields
	Kind Kind `json:"kind"`
}

type JWTIssuerValidatorConfig struct {
	SigningMethod        jwt.SigningMethod
	Issuer               string
	AccessTokenLifeTime  time.Duration
	RefreshTokenLifeTime time.Duration
	SigningKey           interface{}
	ValidationKey        interface{}
}

type JWTIssuerValidator struct {
	config JWTIssuerValidatorConfig
}

func NewJWTIssuerValidator(config JWTIssuerValidatorConfig) *JWTIssuerValidator {
	return &JWTIssuerValidator{
		config: config,
	}
}

func (j *JWTIssuerValidator) issueToken(id *common.UUID, kind Kind, lifeTime time.Duration, extendedFields ExtensionFields) (token *IssuedToken, err error) {
	value, err := jwt.NewWithClaims(j.config.SigningMethod, extendedClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        id.Value,
			Issuer:    j.config.Issuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(lifeTime).Unix(),
		},
		ExtensionFields: extendedFields,
		Kind:            kind,
	}).SignedString(j.config.SigningKey)

	return &IssuedToken{
		Value:    value,
		Id:       id,
		LifeTime: lifeTime,
	}, err
}

func (j *JWTIssuerValidator) IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error) {
	id := utils.NewUUID()
	refreshToken, err = j.issueToken(id, KindRefresh, j.config.RefreshTokenLifeTime, extensionFields)
	if err != nil {
		return
	}
	// do not include extension fields to access token
	accessToken, err = j.issueToken(id, KindAccess, j.config.AccessTokenLifeTime, ExtensionFields{})
	return
}

func (j *JWTIssuerValidator) ValidateToken(token string) (result *ValidationResult, err error) {
	claims := new(extendedClaims)
	tokenObj, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.config.ValidationKey, nil
	})
	if err != nil {
		return
	}
	return &ValidationResult{
		Valid: tokenObj.Valid,
		Id: &common.UUID{
			Value: tokenObj.Claims.(*extendedClaims).Id,
		},
		Kind: tokenObj.Claims.(*extendedClaims).Kind,
	}, nil
}
