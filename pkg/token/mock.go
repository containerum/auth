package token

import (
	"time"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/pkg/utils"
)

type mockTokenRecord struct {
	IssuedAt time.Time
}

type mockIssuerValidator struct {
	returnedLifeTime time.Duration
	issuedTokens     map[string]mockTokenRecord
}

// NewMockIssuerValidator sets up a mock object used for testing purposes
func NewMockIssuerValidator(returnedLifeTime time.Duration) IssuerValidator {
	return &mockIssuerValidator{
		returnedLifeTime: returnedLifeTime,
		issuedTokens:     make(map[string]mockTokenRecord),
	}
}

func (m *mockIssuerValidator) IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error) {
	tokenID := utils.NewUUID()
	now := m.Now()
	accessToken = &IssuedToken{
		Value:    "a" + tokenID,
		LifeTime: m.returnedLifeTime,
		ID:       tokenID,
		IssuedAt: now,
	}
	m.issuedTokens[tokenID] = mockTokenRecord{
		IssuedAt: now,
	}
	refreshToken = &IssuedToken{
		Value:    "r" + tokenID,
		LifeTime: m.returnedLifeTime,
		ID:       tokenID,
		IssuedAt: now,
	}
	return
}

func (m *mockIssuerValidator) ValidateToken(token string) (result *ValidationResult, err error) {
	rec, present := m.issuedTokens[token[1:]]
	var kind Kind
	switch token[0] {
	case 'a':
		kind = KindAccess
	case 'r':
		kind = KindRefresh
	default:
		return nil, autherr.ErrInvalidToken().AddDetailF("bad token kind %s", token[0])
	}
	return &ValidationResult{
		Valid: present && m.Now().Before(rec.IssuedAt.Add(m.returnedLifeTime)),
		Kind:  kind,
		ID:    token[1:],
	}, nil
}

func (m *mockIssuerValidator) AccessFromRefresh(refreshToken string) (accessToken *IssuedToken, err error) {
	if refreshToken[0] != 'r' {
		return nil, autherr.ErrInvalidToken().AddDetailF("bad token kind '%c'", refreshToken[0])
	}
	rec, present := m.issuedTokens[refreshToken[1:]]

	if !present || m.Now().After(rec.IssuedAt.Add(m.returnedLifeTime)) {
		return nil, autherr.ErrInvalidToken()
	}

	return &IssuedToken{
		Value:    "a" + refreshToken[1:],
		ID:       refreshToken[1:],
		IssuedAt: rec.IssuedAt.Truncate(time.Second),
		LifeTime: m.returnedLifeTime,
	}, nil
}

func (m *mockIssuerValidator) Now() time.Time {
	return time.Now().UTC()
}
