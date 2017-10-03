package storages

import (
	"encoding/json"

	"crypto/md5"
	"encoding/hex"

	"errors"

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
		tx.CreateIndex(indexTokens, "*", buntdb.IndexJSON("platform"),
			buntdb.IndexJSON("fingerprint"), buntdb.IndexJSON("user_ip"))
		tx.CreateIndex(indexUsers, "*", buntdb.IndexJSON("user_id.value"))
		return tx.Commit()
	})
	return &BuntDBStorage{
		db:           db,
		tokenFactory: tokenFactory,
	}, err
}

func (*BuntDBStorage) forTokensByIdentity(tx *buntdb.Tx,
	req *auth.CreateTokenRequest,
	iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		Platform:    utils.ShortUserAgent(req.UserAgent),
		UserIp:      req.UserIp,
		Fingerprint: req.Fingerprint,
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
		err := s.forTokensByIdentity(tx, req, func(key, value string) bool {
			tx.Delete(key)
			return true
		})
		return s.commitOrRollback(tx, err)
	})
	if err != nil {
		return nil, err
	}

	// issue tokens
	refreshToken, err := s.tokenFactory.IssueRefreshToken(token.ExtensionFields{
		UserIDHash: hex.EncodeToString(md5.Sum([]byte(req.UserId.Value))[:]),
		Role:       req.UserRole.String(),
	})
	accessToken, err := s.tokenFactory.IssueAccessToken(token.ExtensionFields{})

	// store tokens
	err = s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(refreshToken.Id.Value,
			s.marshalRecord(token.RequestToRecord(req, refreshToken)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		if err != nil {
			return tx.Rollback()
		}
		_, _, err = tx.Set(accessToken.Id.Value,
			s.marshalRecord(token.RequestToRecord(req, accessToken)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     accessToken.LifeTime,
			})
		return s.commitOrRollback(tx, err)
	})

	return &auth.CreateTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, err
}

func (s *BuntDBStorage) CheckToken(ctx context.Context, req *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	valid, id, err := s.tokenFactory.ValidateToken(req.AccessToken)
	if err != nil || !valid {
		return nil, errors.New("invalid token received")
	}
	var rec *auth.StoredToken
	err = s.db.View(func(tx *buntdb.Tx) error {
		rawRec, err := tx.Get(id.Value)
		if err != nil {
			return err
		}
		rec = s.unmarshalRecord(rawRec)
		return nil
	})
	if err != nil {
		return nil, err
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
