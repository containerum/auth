package storages

import (
	"encoding/hex"

	"crypto/sha256"

	"time"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/pkg/token"
	"git.containerum.net/ch/auth/pkg/utils"
	"git.containerum.net/ch/auth/proto"
	"github.com/containerum/cherry"
	"github.com/containerum/cherry/adaptors/cherrylog"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
	"golang.org/x/net/context"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	indexTokens = "tokens"
	indexUsers  = "users"
)

// BuntDBStorageConfig is a configuration for token storage
type BuntDBStorageConfig struct {
	File         string
	BuntDBConfig buntdb.Config
	TokenFactory token.IssuerValidator
}

// BuntDBStorage is a token storage which uses BuntDB library.
// It must implement Auth interface (defined in grpc-proto-files).
// Methods implementing it should retreive only grpc errors
type BuntDBStorage struct {
	db     *buntdb.DB
	logger *cherrylog.LogrusAdapter
	BuntDBStorageConfig
}

// NewBuntDBStorage initializes and returns token storage
func NewBuntDBStorage(config BuntDBStorageConfig) (storage *BuntDBStorage, err error) {
	logger := logrus.WithField("component", "BuntDBStorage")
	logger.WithField("config", config).Info("Initializing BuntDBStorage")

	logger.Debugf("Opening file %s", config.File)
	db, err := buntdb.Open(config.File)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Setting database config")
	if cfgErr := db.SetConfig(config.BuntDBConfig); cfgErr != nil {
		return nil, cfgErr
	}

	err = db.Update(func(tx *buntdb.Tx) error {
		logger.Debugf("Create index for tokens")
		if txErr := tx.CreateIndex(indexTokens, "*", buntdb.IndexJSON("platform"),
			buntdb.IndexJSON("fingerprint"), buntdb.IndexJSON("user_ip")); txErr != nil {
			return txErr
		}
		logger.Debugf("Create index for users")
		if txErr := tx.CreateIndex(indexUsers, "*", buntdb.IndexJSON("user_id")); txErr != nil {
			return txErr
		}
		return nil
	})
	return &BuntDBStorage{
		db:                  db,
		BuntDBStorageConfig: config,
		logger:              cherrylog.NewLogrusAdapter(logger),
	}, err
}

type tokenOwnerIdentity struct {
	UserAgent, UserIP, Fingerprint string
}

func (s *BuntDBStorage) forTokensByIdentity(tx *buntdb.Tx,
	identity *tokenOwnerIdentity,
	iterator func(key, value string) bool) error {
	pivot, err := json.Marshal(authProto.StoredToken{
		Platform:    utils.ShortUserAgent(identity.UserAgent),
		UserIp:      identity.UserIP,
		Fingerprint: identity.Fingerprint,
	})
	s.logger.WithError(err).WithField("pivot", string(pivot)).Debugf("Iterating by identity")
	return tx.AscendEqual(indexTokens, string(pivot), iterator)
}

func (s *BuntDBStorage) forTokensByUsers(tx *buntdb.Tx, userID string, iterator func(key, value string) bool) error {
	pivot, err := json.Marshal(authProto.StoredToken{
		UserId: userID,
	})
	s.logger.WithError(err).WithField("pivot", string(pivot)).Debugf("Iterating by user")
	return tx.AscendEqual(indexUsers, string(pivot), iterator)
}

func (s *BuntDBStorage) marshalRecord(st *authProto.StoredToken) string {
	ret, err := json.Marshal(st)
	s.logger.WithError(err).WithField("record", st).Debugf("Marshal record")
	return string(ret)
}

func (s *BuntDBStorage) unmarshalRecord(rawRecord string) *authProto.StoredToken {
	ret := new(authProto.StoredToken)
	err := json.Unmarshal([]byte(rawRecord), ret)
	s.logger.WithError(err).WithField("rawRecord", rawRecord).Debugf("Unmarshal record")
	return ret
}

func (s *BuntDBStorage) deleteTokenByIdentity(tx *buntdb.Tx, identity *tokenOwnerIdentity) error {
	s.logger.WithField("identity", identity).Debugf("Delete token by identity")

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

func (s *BuntDBStorage) deleteTokenByUser(tx *buntdb.Tx, userID string) error {
	s.logger.WithField("userId", userID).Debugf("Delete token by user")

	var keysToDelete []string
	err := s.forTokensByUsers(tx, userID, func(key, value string) bool {
		keysToDelete = append(keysToDelete, key)
		return true
	})
	if err != nil {
		return err
	}
	for _, v := range keysToDelete {
		if _, err := tx.Delete(v); err != nil {
			return s.handleDeleteError(err)
		}
	}
	return nil
}

func (s *BuntDBStorage) wrapTXError(err error) error {
	switch err.(type) {
	case nil:
		return nil
	case *cherry.Err:
		return err
	default:
		return autherr.ErrInternal().AddDetailsErr(err).Log(err, s.logger)
	}
}

func (s *BuntDBStorage) handleGetError(err error) error {
	switch err {
	case buntdb.ErrNotFound:
		return autherr.ErrTokenNotFound().Log(err, s.logger)
	default:
		return autherr.ErrInternal().AddDetailsErr(err).Log(err, s.logger)
	}
}

func (s *BuntDBStorage) handleDeleteError(err error) error {
	switch err {
	case buntdb.ErrNotFound:
		return autherr.ErrTokenNotFound().Log(err, s.logger)
	default:
		return autherr.ErrInternal().AddDetailsErr(err).Log(err, s.logger)
	}
}

// CreateToken creates token with parameters given in req.
func (s *BuntDBStorage) CreateToken(ctx context.Context, req *authProto.CreateTokenRequest) (*authProto.CreateTokenResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Info("Creating token")
	var accessToken, refreshToken *token.IssuedToken
	err := s.db.Update(func(tx *buntdb.Tx) error {
		// remove already exist tokens
		logger.Debug("Remove already exist tokens")
		if err := s.deleteTokenByIdentity(tx, &tokenOwnerIdentity{
			UserAgent:   req.GetUserAgent(),
			UserIP:      req.GetUserIp(),
			Fingerprint: req.GetFingerprint(),
		}); err != nil {
			return err
		}

		// issue tokens
		var err error
		userIDHash := sha256.Sum256([]byte(req.GetUserId()))
		logger.WithField("userIDHash", userIDHash).Debug("Issue tokens")
		accessToken, refreshToken, err = s.TokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash:  hex.EncodeToString(userIDHash[:]),
			Role:        req.GetUserRole(),
			PartTokenID: req.GetPartTokenId(),
		})
		if err != nil {
			s.logger.WithError(err).Error("token issue failed")
			return autherr.ErrInternal().AddDetailsErr(err).Log(err, s.logger)
		}

		// store tokens
		logger.WithField("accessToken", accessToken).
			WithField("refreshToken", refreshToken).
			Debugf("Store tokens")
		_, _, err = tx.Set(refreshToken.ID,
			s.marshalRecord(token.RequestToRecord(req, refreshToken)),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		return err
	})
	if err != nil {
		return nil, s.wrapTXError(err)
	}

	return &authProto.CreateTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

// CheckToken checks user token. Only access token may be checked.
// errInvalidToken will be returned if token expired, cannot be parsed or it is not access token
// errTokenNotOwnedBySender returned if user IP or fingerprint not matches with recorded at token creation.
func (s *BuntDBStorage) CheckToken(ctx context.Context, req *authProto.CheckTokenRequest) (*authProto.CheckTokenResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Validating token")
	valid, err := s.TokenFactory.ValidateToken(req.GetAccessToken())
	if err != nil || !valid.Valid || valid.Kind != token.KindAccess {
		return nil, autherr.ErrInvalidToken()
	}
	var rec *authProto.StoredToken
	logger.Debugf("Find record in storage")
	err = s.db.View(func(tx *buntdb.Tx) error {
		rawRec, getErr := tx.Get(valid.ID)
		if getErr != nil {
			return s.handleGetError(getErr)
		}
		println(rawRec)
		rec = s.unmarshalRecord(rawRec)
		return nil
	})
	if txErr := s.wrapTXError(err); txErr != nil {
		return nil, err
	}
	if rec.GetUserIp() != req.GetUserIp() || rec.GetFingerprint() != req.GetFingerPrint() {
		return nil, autherr.ErrTokenNotOwnedBySender()
	}

	return &authProto.CheckTokenResponse{
		Access: &authProto.ResourcesAccess{
			Namespace: token.DecodeAccessObjects(rec.UserNamespace),
			Volume:    token.DecodeAccessObjects(rec.UserVolume),
		},
		UserId:      rec.UserId,
		UserRole:    rec.UserRole,
		TokenId:     rec.TokenId,
		PartTokenId: rec.PartTokenId,
	}, nil
}

// ExtendToken exchanges valid refresh token to new access and refresh tokens.
func (s *BuntDBStorage) ExtendToken(ctx context.Context, req *authProto.ExtendTokenRequest) (*authProto.ExtendTokenResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Info("Extend token")

	// validate received token
	logger.Debugf("Validate token")
	valid, err := s.TokenFactory.ValidateToken(req.GetRefreshToken())
	if err != nil {
		s.logger.WithError(err).Info("malformed token received")
		return nil, autherr.ErrInvalidToken().Log(err, s.logger)
	}
	if !valid.Valid || valid.Kind != token.KindRefresh {
		return nil, autherr.ErrInvalidToken()
	}

	var accessToken, refreshToken *token.IssuedToken
	err = s.db.Update(func(tx *buntdb.Tx) error {
		// identify token owner
		logger.Debugf("Identify token owner")
		rawRec, txErr := tx.Get(valid.ID)
		if txErr != nil {
			return s.handleGetError(txErr)
		}
		rec := s.unmarshalRecord(rawRec)
		if rec.GetFingerprint() != req.GetFingerprint() {
			return autherr.ErrTokenNotOwnedBySender()
		}

		// remove old tokens
		logger.WithField("record", rec).Debugf("Delete old token")
		if delErr := s.deleteTokenByIdentity(tx, &tokenOwnerIdentity{
			UserAgent:   rec.GetUserAgent(),
			UserIP:      rec.GetUserIp(),
			Fingerprint: rec.GetFingerprint(),
		}); delErr != nil {
			return delErr
		}

		// issue new tokens
		userIDHash := sha256.Sum256([]byte(rec.GetUserId()))
		logger.WithField("userIDHash", userIDHash).Debug("Issue new tokens")
		accessToken, refreshToken, txErr = s.TokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash: hex.EncodeToString(userIDHash[:]),
			Role:       rec.UserRole,
		})
		if txErr != nil {
			s.logger.WithError(txErr).Error("token issue failed")
			return autherr.ErrInternal().Log(txErr, s.logger)
		}
		refreshTokenRecord := *rec
		refreshTokenRecord.TokenId = refreshToken.ID
		refreshTokenRecord.RawRefreshToken = refreshToken.Value
		refreshTokenRecord.CreatedAt, _ = ptypes.TimestampProto(refreshToken.IssuedAt)

		// store new tokens
		logger.WithField("record", refreshTokenRecord).Debug("Store new tokens")
		_, _, txErr = tx.Set(refreshToken.ID,
			s.marshalRecord(&refreshTokenRecord),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		return txErr
	})

	if err = s.wrapTXError(err); err != nil {
		return nil, err
	}

	return &authProto.ExtendTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}

// UpdateAccess updates resources accesses for user.
func (s *BuntDBStorage) UpdateAccess(ctx context.Context, req *authProto.UpdateAccessRequest) (*empty.Empty, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Update auth")
	now := s.TokenFactory.Now()
	err := s.db.Update(func(tx *buntdb.Tx) error {
		for _, entry := range req.GetUsers() {
			if entry == nil {
				continue
			}
			kvToUpdate := make(map[string]*authProto.StoredToken)
			var setErr error
			iterErr := s.forTokensByUsers(tx, entry.GetUserId(), func(key, value string) bool {
				rec := s.unmarshalRecord(value)
				rec.UserVolume = token.EncodeAccessObjects(entry.GetAccess().GetVolume())
				rec.UserNamespace = token.EncodeAccessObjects(entry.GetAccess().GetNamespace())
				kvToUpdate[key] = rec
				return true
			})
			if iterErr != nil {
				return iterErr
			}
			for key, rec := range kvToUpdate {
				value := s.marshalRecord(rec)
				var createdAt time.Time
				if createdAt, setErr = ptypes.Timestamp(rec.CreatedAt); setErr != nil {
					return setErr
				}
				var lifeTime time.Duration
				if lifeTime, setErr = ptypes.Duration(rec.LifeTime); setErr != nil {
					return setErr
				}
				_, _, setErr = tx.Set(key, value, &buntdb.SetOptions{
					Expires: true,
					TTL:     createdAt.Add(lifeTime).Sub(now), // set TTL to difference between end-of-life time and now
				})
				if setErr != nil {
					return setErr
				}
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, s.wrapTXError(err)
	}
	return &empty.Empty{}, nil
}

// GetUserTokens returns meta information (token id, user agent, user IP) for user
func (s *BuntDBStorage) GetUserTokens(ctx context.Context, req *authProto.GetUserTokensRequest) (*authProto.GetUserTokensResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Get user tokens")
	resp := new(authProto.GetUserTokensResponse)
	err := s.db.View(func(tx *buntdb.Tx) error {
		return s.forTokensByUsers(tx, req.GetUserId(), func(key, value string) bool {
			rec := s.unmarshalRecord(value)
			resp.Tokens = append(resp.Tokens, &authProto.StoredTokenForUser{
				TokenId:   rec.TokenId,
				UserAgent: rec.UserAgent,
				Ip:        rec.UserIp,
				CreatedAt: rec.CreatedAt.String(),
			})
			return true
		})
	})
	return resp, s.wrapTXError(err)
}

// DeleteToken deletes token for user.
// ErrTokenNotOwnerBySender returned if token owner id not matches id in request
func (s *BuntDBStorage) DeleteToken(ctx context.Context, req *authProto.DeleteTokenRequest) (*empty.Empty, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Delete token")
	return new(empty.Empty), s.wrapTXError(s.db.Update(func(tx *buntdb.Tx) error {
		value, err := tx.Delete(req.GetTokenId())
		if err != nil {
			return s.handleDeleteError(err)
		}
		rec := s.unmarshalRecord(value)
		if rec.GetUserId() != req.GetUserId() {
			err = autherr.ErrTokenNotOwnedBySender()
		}
		return err
	}))
}

// DeleteUserTokens deletes all user tokens
func (s *BuntDBStorage) DeleteUserTokens(ctx context.Context, req *authProto.DeleteUserTokensRequest) (*empty.Empty, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Delete user tokens")
	return new(empty.Empty), s.wrapTXError(s.db.Update(func(tx *buntdb.Tx) error {
		return s.deleteTokenByUser(tx, req.GetUserId())
	}))
}

// AccessTokenByID returns user access token
func (s *BuntDBStorage) AccessTokenByID(ctx context.Context, req *authProto.AccessTokenByIDRequest) (*authProto.AccessTokenByIDResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Info("Get access token by ID")
	var accessToken *token.IssuedToken
	err := s.db.View(func(tx *buntdb.Tx) error {
		rawRec, getErr := tx.Get(req.GetTokenId())
		if getErr != nil {
			return s.handleGetError(getErr)
		}

		rec := s.unmarshalRecord(rawRec)
		var reconstructErr error
		accessToken, reconstructErr = s.TokenFactory.AccessFromRefresh(rec.RawRefreshToken)
		return reconstructErr
	})
	if err != nil {
		return nil, s.wrapTXError(err)
	}
	return &authProto.AccessTokenByIDResponse{
		AccessToken: accessToken.Value,
	}, nil
}

// Close implements closer interface
func (s *BuntDBStorage) Close() error {
	s.logger.Info("Closing database")
	return s.db.Close()
}
