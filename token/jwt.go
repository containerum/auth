package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/dgrijalva/jwt-go"
)

func NewJWTIssuerValidator(config JWTIssuerValidatorConfig) *JWTIssuerValidator {
	return &JWTIssuerValidator{
		config: config,
	}
}

func (j *JWTIssuerValidator) issueToken(claims ourClaims, lifetime time.Duration) (token *IssuedToken, err error) {
	idBytes := make([]byte, JWTIDLength)
	rand.Read(idBytes)

	token = &IssuedToken{
		Id: &common.UUID{
			Value: hex.EncodeToString(idBytes[:]),
		},
		LifeTime: lifetime,
	}
	claims.Id = token.Id.Value // expose token ID
	token.Value, err = jwt.NewWithClaims(j.config.SigningMethod, claims).SignedString(j.config.SigningKey)
	return token, err
}

func (j *JWTIssuerValidator) IssueAccessToken(e ExtensionFields) (token *IssuedToken, err error) {
	now := time.Now()
	return j.issueToken(ourClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    j.config.Issuer,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(j.config.AccessTokenLifeTime).Unix(),
		},
		ExtensionFields: e,
	}, j.config.AccessTokenLifeTime)
}

func (j *JWTIssuerValidator) IssueRefreshToken(e ExtensionFields) (token *IssuedToken, err error) {
	now := time.Now()
	return j.issueToken(ourClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    j.config.Issuer,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(j.config.RefreshTokenLifeTime).Unix(),
		},
		ExtensionFields: e,
	}, j.config.RefreshTokenLifeTime)
}

func (j *JWTIssuerValidator) ValidateToken(token string) (bool, error) {
	claims := make(jwt.MapClaims)
	tokenObj, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.config.ValidationKey, nil
	})
	if err != nil {
		return false, err
	}
	return tokenObj.Valid, nil
}
