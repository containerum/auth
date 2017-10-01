package token

import (
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
)

type ExtensionFields struct {
	UserIDHash string `json:"userID"`
	Role       string `json:"role"`
}

type IssuedToken struct {
	Value string
	Id *common.UUID
	LifeTime time.Duration
}

// Issuer is interface for creating access and refresh tokens.
type Issuer interface {
	IssueAccessToken(ExtensionFields) (token *IssuedToken, err error)
	IssueRefreshToken(ExtensionFields) (token *IssuedToken, err error)
}

// Validator is interface for validating tokens
type Validator interface {
	ValidateToken(token string, fields ExtensionFields) (bool, error)
}

type IssuerValidator interface {
	Issuer
	Validator
}
