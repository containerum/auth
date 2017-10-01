package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/dgrijalva/jwt-go"
)

const JWTIDLength = 16

type accessTokenClaims struct {
	jwt.StandardClaims
	ExtensionFields
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

func NewTokenFactory(config JWTIssuerValidatorConfig) *JWTIssuerValidator {
	return &JWTIssuerValidator{
		config: config,
	}
}

func (j *JWTIssuerValidator) IssueAccessToken(e ExtensionFields) (token *IssuedToken, err error) {
	idBytes := make([]byte, JWTIDLength)
	rand.Read(idBytes)
	now := time.Now()

	token = new(IssuedToken)
	token.Id = &common.UUID{
		Value: hex.EncodeToString(idBytes[:]),
	}
	token.Value, err = jwt.NewWithClaims(j.config.SigningMethod, accessTokenClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    j.config.Issuer,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(j.config.AccessTokenLifeTime).Unix(),
			Id:        token.Id.Value,
		},
		ExtensionFields: e,
	}).SignedString(j.config.SigningKey)
	return token, err
}

func (j *JWTIssuerValidator) IssueRefreshToken(ExtensionFields) (token *IssuedToken, err error) {
	idBytes := make([]byte, JWTIDLength)
	rand.Read(idBytes)
	now := time.Now()

	token = new(IssuedToken)
	token.Id = &common.UUID{
		Value: hex.EncodeToString(idBytes[:]),
	}
	token.Value, err = jwt.NewWithClaims(j.config.SigningMethod, jwt.StandardClaims{
		Issuer:    j.config.Issuer,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(j.config.RefreshTokenLifeTime).Unix(),
		Id:        token.Id.Value,
	}).SignedString(j.config.SigningKey)
	return token, err
}

func (j *JWTIssuerValidator) ValidateToken(token string, fields ExtensionFields) (bool, error) {
	claims := make(jwt.MapClaims)
	tokenObj, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.config.ValidationKey, nil
	})
	if err != nil {
		return false, err
	}
	return tokenObj.Valid, nil
}
