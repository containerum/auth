package token

import (
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/dgrijalva/jwt-go"
)

type ExtensionFields struct {
	UserIDHash string `json:"userID,omitempty"`
	Role       string `json:"role,omitempty"`
}

type IssuedToken struct {
	Value    string
	Id       *common.UUID
	LifeTime time.Duration
}

// Issuer is interface for creating access and refresh tokens.
type Issuer interface {
	IssueAccessToken(ExtensionFields) (token *IssuedToken, err error)
	IssueRefreshToken(ExtensionFields) (token *IssuedToken, err error)
}

// Validator is interface for validating tokens
type Validator interface {
	ValidateToken(token string) (bool, error)
}

type IssuerValidator interface {
	Issuer
	Validator
}

const JWTIDLength = 16

type ourClaims struct {
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
