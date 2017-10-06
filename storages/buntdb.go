package storages

import (
	"encoding/json"

	"crypto/md5"
	"encoding/hex"

	"bitbucket.org/exonch/ch-auth/token"
	"bitbucket.org/exonch/ch-auth/utils"
	"bitbucket.org/exonch/ch-grpc/auth"
	"bitbucket.org/exonch/ch-grpc/common"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/tidwall/buntdb"
	"golang.org/x/net/context"
)

const (
	indexTokens = "tokens"
	indexUsers  = "users"
)

// TokenStorage using BuntDB library
type BuntDBStorage struct {
	db           *buntdb.DB
	tokenFactory token.IssuerValidator
}

func NewBuntDBStorage(file string, tokenFactory token.IssuerValidator) (storage *BuntDBStorage, err error) {
	db, err := buntdb.Open(file)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *buntdb.Tx) error {
		if err := tx.CreateIndex(indexTokens, "*", buntdb.IndexJSON("platform"),
			buntdb.IndexJSON("fingerprint"), buntdb.IndexJSON("user_ip")); err != nil {
			return err
		}
		if err := tx.CreateIndex(indexUsers, "*", buntdb.IndexJSON("user_id.value")); err != nil {
			return err
		}
		return nil
	})
	return &BuntDBStorage{
		db:           db,
		tokenFactory: tokenFactory,
	}, err
}

type tokenOwnerIdentity struct {
	UserAgent, UserIp, Fingerprint string
}

func (*BuntDBStorage) forTokensByIdentity(tx *buntdb.Tx,
	identity *tokenOwnerIdentity,
	iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		Platform:    utils.ShortUserAgent(identity.UserAgent),
		UserIp:      identity.UserIp,
		Fingerprint: identity.Fingerprint,
	})
	return tx.AscendEqual(indexTokens, string(pivot), iterator)
}

func (*BuntDBStorage) forTokensByUsers(tx *buntdb.Tx, UserId string, iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		UserId: &common.UUID{
			Value: UserId,
		},
	})
	return tx.AscendEqual(indexUsers, string(pivot), iterator)
}

func (*BuntDBStorage) marshalRecord(st *auth.StoredToken) string {
	ret, _ := json.Marshal(st)
	return string(ret)
}

func (*BuntDBStorage) unmarshalRecord(rawRecord string) *auth.StoredToken {
	ret := new(auth.StoredToken)
	json.Unmarshal([]byte(rawRecord), ret)
	return ret
}

func (s *BuntDBStorage) deleteTokenByIdentity(tx *buntdb.Tx, identity *tokenOwnerIdentity) error {
	var keysToDelete []string
	err := s.forTokensByIdentity(tx, identity, func(key, value string) bool {
		keysToDelete = append(keysToDelete, key)
		return true
	})
	if err != nil {
		return err
	}
	for _, v := range keysToDelete {
		if _, err := tx.Delete(v); err != nil {
			return err
		}
	}
	return nil
}

func (s *BuntDBStorage) deleteTokenByUser(tx *buntdb.Tx, userId *common.UUID) error {
	var keysToDelete []string
	err := s.forTokensByUsers(tx, userId.Value, func(key, value string) bool {
		keysToDelete = append(keysToDelete, key)
		return true
	})
	if err != nil {
		return err
	}
	for _, v := range keysToDelete {
		if _, err := tx.Delete(v); err != nil {
			return err
		}
	}
	return nil
}

func (s *BuntDBStorage) CreateToken(ctx context.Context, req *auth.CreateTokenRequest) (*auth.CreateTokenResponse, error) {
	var accessToken, refreshToken *token.IssuedToken
	err := s.db.Update(func(tx *buntdb.Tx) error {
		// remove already exist tokens
		if err := s.deleteTokenByIdentity(tx, &tokenOwnerIdentity{
			UserAgent:   req.UserAgent,
			UserIp:      req.UserIp,
			Fingerprint: req.Fingerprint,
		}); err != nil {
			return err
		}

		// issue tokens
		var err error
		userIdHash := md5.Sum([]byte(req.UserId.Value))
		accessToken, refreshToken, err = s.tokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash: hex.EncodeToString(userIdHash[:]),
			Role:       req.UserRole.String(),
		})
		if err != nil {
			return err
		}

		//store tokens
		_, _, err = tx.Set(refreshToken.Id.Value,
			s.marshalRecord(token.RequestToRecord(req, refreshToken)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		return err
	})

	return &auth.CreateTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, err
}

func (s *BuntDBStorage) CheckToken(ctx context.Context, req *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	valid, err := s.tokenFactory.ValidateToken(req.AccessToken)
	if err != nil || !valid.Valid || valid.Kind != token.KindAccess { // only access tokens may be checked
		return nil, ErrInvalidToken
	}
	var rec *auth.StoredToken
	err = s.db.View(func(tx *buntdb.Tx) error {
		rawRec, err := tx.Get(valid.Id.Value)
		if err != nil {
			return err
		}
		rec = s.unmarshalRecord(rawRec)
		return nil
	})
	if err != nil || rec.UserIp != req.UserIp || rec.Fingerprint != req.FingerPrint {
		return nil, ErrTokenNotOwnedBySender
	}

	return &auth.CheckTokenResponse{
		Access: &auth.ResourcesAccess{
			Namespace: token.DecodeAccessObjects(rec.UserNamespace),
			Volume:    token.DecodeAccessObjects(rec.UserVolume),
		},
		UserId:      rec.UserId,
		UserRole:    rec.UserRole,
		TokenId:     rec.TokenId,
		PartTokenId: rec.PartTokenId,
	}, nil
}

func (s *BuntDBStorage) ExtendToken(ctx context.Context, req *auth.ExtendTokenRequest) (*auth.ExtendTokenResponse, error) {
	// validate received token
	valid, err := s.tokenFactory.ValidateToken(req.RefreshToken)
	if err != nil || !valid.Valid || valid.Kind != token.KindRefresh { // user must send refresh token
		return nil, ErrInvalidToken
	}

	var accessToken, refreshToken *token.IssuedToken
	err = s.db.Update(func(tx *buntdb.Tx) error {
		// identify token owner
		rawRec, err := tx.Get(valid.Id.Value)
		if err != nil {
			return err
		}
		rec := s.unmarshalRecord(rawRec)
		if rec.Fingerprint != req.Fingerprint {
			return ErrTokenNotOwnedBySender
		}

		// remove old tokens
		if err := s.deleteTokenByIdentity(tx, &tokenOwnerIdentity{
			UserAgent:   rec.UserAgent,
			UserIp:      rec.UserIp,
			Fingerprint: rec.Fingerprint,
		}); err != nil {
			return err
		}

		// issue new tokens
		userIdHash := md5.Sum([]byte(rec.UserId.Value))
		accessToken, refreshToken, err = s.tokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash: hex.EncodeToString(userIdHash[:]),
			Role:       rec.UserRole.String(),
		})
		if err != nil {
			return err
		}
		refreshTokenRecord := *rec
		refreshTokenRecord.TokenId = refreshToken.Id

		// store new tokens
		_, _, err = tx.Set(refreshToken.Id.Value,
			s.marshalRecord(&refreshTokenRecord),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		return err
	})

	return &auth.ExtendTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, err
}

func (*BuntDBStorage) UpdateAccess(context.Context, *auth.UpdateAccessRequest) (*empty.Empty, error) {
	panic("implement me")
}

func (s *BuntDBStorage) GetUserTokens(ctx context.Context, req *auth.GetUserTokensRequest) (*auth.GetUserTokensResponse, error) {
	resp := new(auth.GetUserTokensResponse)
	err := s.db.View(func(tx *buntdb.Tx) error {
		return s.forTokensByUsers(tx, req.UserId.Value, func(key, value string) bool {
			rec := s.unmarshalRecord(value)
			resp.Tokens = append(resp.Tokens, &auth.StoredTokenForUser{
				TokenId:   rec.TokenId,
				UserAgent: rec.UserAgent,
				Ip:        rec.UserIp,
				// CreatedAt is not stored in db
			})
			return true
		})
	})
	return resp, err
}

func (s *BuntDBStorage) DeleteToken(ctx context.Context, req *auth.DeleteTokenRequest) (*empty.Empty, error) {
	return new(empty.Empty), s.db.Update(func(tx *buntdb.Tx) error {
		value, err := tx.Delete(req.TokenId.Value)
		if err != nil {
			return err
		}
		rec := s.unmarshalRecord(value)
		if !utils.UUIDEquals(rec.UserId, req.UserId) {
			err = ErrTokenNotOwnedBySender
		}
		return err
	})
}

func (s *BuntDBStorage) DeleteUserTokens(ctx context.Context, req *auth.DeleteUserTokensRequest) (*empty.Empty, error) {
	return new(empty.Empty), s.db.Update(func(tx *buntdb.Tx) error {
		return s.deleteTokenByUser(tx, req.UserId)
	})
}

// Implement Closer interface
func (s *BuntDBStorage) Close() error {
	return s.db.Close()
}
