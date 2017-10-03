package token

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"bitbucket.org/exonch/ch-auth/utils"
	"bitbucket.org/exonch/ch-grpc/auth"
	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/dgrijalva/jwt-go"
)

type ExtensionFields struct {
	UserIDHash  string `json:"userID,omitempty"`
	Role        string `json:"role,omitempty"`
	PartTokenId string `json:"partTokenID,omitempty"`
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

func EncodeAccessObjects(req []*auth.AccessObject) string {
	ret, _ := json.Marshal(req)
	return base64.StdEncoding.EncodeToString(ret)
}

func RequestToRecord(req *auth.CreateTokenRequest, token *IssuedToken) *auth.StoredToken {
	return &auth.StoredToken{
		TokenId:       token.Id,
		UserAgent:     req.UserAgent,
		Platform:      utils.ShortUserAgent(req.UserAgent),
		Fingerprint:   req.Fingerprint,
		UserId:        req.UserId,
		UserRole:      req.UserRole,
		UserNamespace: EncodeAccessObjects(req.Access.Namespace),
		UserVolume:    EncodeAccessObjects(req.Access.Volume),
		RwAccess:      req.RwAccess,
		UserIp:        req.UserIp,
		PartTokenId:   req.PartTokenId,
	}
}
