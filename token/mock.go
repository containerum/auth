package token

import (
	"time"

	"bitbucket.org/exonch/ch-auth/utils"
	"bitbucket.org/exonch/ch-grpc/common"
)

var _ IssuerValidator = &MockIssuerValidator{}

type mockTokenRecord struct {
	IssuedAt time.Time
	Kind     Kind
}

type MockIssuerValidator struct {
	returnedLifeTime time.Duration
	issuedTokens     map[string]mockTokenRecord
}

func NewMockIssuerValidator(returnedLifeTime time.Duration) *MockIssuerValidator {
	return &MockIssuerValidator{
		returnedLifeTime: returnedLifeTime,
		issuedTokens:     make(map[string]mockTokenRecord),
	}
}

func (m *MockIssuerValidator) IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error) {
	tokenId := utils.NewUUID()
	accessToken = &IssuedToken{
		Value:    tokenId.Value,
		LifeTime: m.returnedLifeTime,
		Id:       tokenId,
	}
	m.issuedTokens[tokenId.Value] = mockTokenRecord{
		IssuedAt: time.Now(),
		Kind:     KindAccess,
	}
	refreshToken = accessToken
	return
}

func (m *MockIssuerValidator) ValidateToken(token string) (result *ValidationResult, err error) {
	rec, present := m.issuedTokens[token]
	return &ValidationResult{
		Valid: present && time.Now().Before(rec.IssuedAt.Add(m.returnedLifeTime)),
		Kind:  rec.Kind,
		Id:    &common.UUID{Value: token},
	}, nil
}
