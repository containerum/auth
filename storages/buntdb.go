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
		tx.CreateIndex(indexTokens, "*", buntdb.IndexJSON("Platform"),
			buntdb.IndexJSON("Fingerprint"), buntdb.IndexJSON("UserIP"))
		tx.CreateIndex(indexUsers, "*", buntdb.IndexJSON("UserId.value"))
		return tx.Commit()
	})
	return &BuntDBStorage{
		db:           db,
		tokenFactory: tokenFactory,
	}, err
}

func (*BuntDBStorage) forTokensByIdentity(tx *buntdb.Tx,
	userAgent, fingerprint, ip string,
	iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		Platform:    utils.ShortUserAgent(userAgent),
		UserIp:      ip,
		Fingerprint: fingerprint,
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

func (*BuntDBStorage) commitOrRollback(tx *buntdb.Tx, err error) error {
	if err != nil {
		return tx.Rollback()
	} else {
		return tx.Commit()
	}
}

func (s *BuntDBStorage) CreateToken(ctx context.Context, req *auth.CreateTokenRequest) (*auth.CreateTokenResponse, error) {
	// remove already exist tokens
	err := s.db.Update(func(tx *buntdb.Tx) error {
		err := s.forTokensByIdentity(tx, req.UserAgent, req.Fingerprint, req.UserIp, func(key, value string) bool {
			tx.Delete(key)
			return true
		})
		return s.commitOrRollback(tx, err)
	})
	if err != nil {
		return nil, err
	}

	// issue tokens
	refreshToken, refreshTokenID, refreshTokenLifeTime, err := s.tokenFactory.IssueRefreshToken(token.ExtensionFields{
		UserIDHash: hex.EncodeToString(md5.Sum([]byte(req.UserId.Value))[:]),
		Role:       req.UserRole.String(),
	})
	accessToken, accessTokenID, accessTokenLifeTime, err := s.tokenFactory.IssueAccessToken(token.ExtensionFields{})

	// store tokens
	err = s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(refreshTokenID.Value,
			s.marshalRecord(utils.RequestToRecord(req, refreshTokenID)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshTokenLifeTime,
			})
		_, _, err = tx.Set(accessTokenID.Value,
			s.marshalRecord(utils.RequestToRecord(req, accessTokenID)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     accessTokenLifeTime,
			})
		if err != nil {
			return tx.Rollback()
		}
		_, _, err = tx.Set(accessTokenID.Value, s.marshalRecord(utils.RequestToRecord(req, accessTokenID)), nil)
		return s.commitOrRollback(tx, err)
	})

	return &auth.CreateTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, err
}

func (*BuntDBStorage) CheckToken(context.Context, *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	panic("implement me")
}

func (*BuntDBStorage) ExtendToken(context.Context, *auth.ExtendTokenRequest) (*auth.ExtendTokenResponse, error) {
	panic("implement me")
}

func (*BuntDBStorage) UpdateAccess(context.Context, *auth.UpdateAccessRequest) (*empty.Empty, error) {
	panic("implement me")
}

func (*BuntDBStorage) GetUserTokens(context.Context, *auth.GetUserTokensRequest) (*auth.GetUserTokensResponse, error) {
	panic("implement me")
}

func (*BuntDBStorage) DeleteToken(context.Context, *auth.DeleteTokenRequest) (*empty.Empty, error) {
	panic("implement me")
}

func (*BuntDBStorage) DeleteUserTokens(context.Context, *auth.DeleteUserTokensRequest) (*empty.Empty, error) {
	panic("implement me")
}
