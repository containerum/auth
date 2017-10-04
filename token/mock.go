package token

import (
	"time"

	"bitbucket.org/exonch/ch-auth/utils"
	"bitbucket.org/exonch/ch-grpc/common"
)

type MockIssuerValidator struct {
	returnedLifeTime time.Duration
	issuedTokens     map[string]time.Time
}

func NewMockIssuerValidator(returnedLifeTime time.Duration) *MockIssuerValidator {
	return &MockIssuerValidator{
		returnedLifeTime: returnedLifeTime,
		issuedTokens: make(map[string]time.Time),
	}
}

func (m *MockIssuerValidator) IssueAccessToken(ExtensionFields) (token *IssuedToken, err error) {
	id := utils.NewUUID()
	m.issuedTokens[id.Value] = time.Now()
	return &IssuedToken{
		Value:    id.Value,
		Id:       id,
		LifeTime: m.returnedLifeTime,
	}, nil
}

func (m *MockIssuerValidator) IssueRefreshToken(ExtensionFields) (token *IssuedToken, err error) {
	id := utils.NewUUID()
	m.issuedTokens[id.Value] = time.Now()
	return &IssuedToken{
		Value:    id.Value,
		Id:       utils.NewUUID(),
		LifeTime: m.returnedLifeTime,
	}, nil
}

func (m *MockIssuerValidator) ValidateToken(token string) (valid bool, tokenId *common.UUID, err error) {
	issTime, present := m.issuedTokens[token]
	if !present || time.Now().After(issTime.Add(m.returnedLifeTime)) {
		return false, nil, nil
	}
	return true, &common.UUID{Value: token}, nil
}
