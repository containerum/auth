package storages

import (
	"encoding/hex"

	"crypto/sha256"

	"git.containerum.net/ch/auth/token"
	"git.containerum.net/ch/auth/utils"
	"git.containerum.net/ch/grpc-proto-files/auth"
	"git.containerum.net/ch/grpc-proto-files/common"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
	"golang.org/x/net/context"
	"google.golang.org/grpc/status"
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
	logger *logrus.Entry
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
		if txErr := tx.CreateIndex(indexUsers, "*", buntdb.IndexJSON("user_id.value")); txErr != nil {
			return txErr
		}
		return nil
	})
	return &BuntDBStorage{
		db:                  db,
		BuntDBStorageConfig: config,
		logger:              logger,
	}, err
}

type tokenOwnerIdentity struct {
	UserAgent, UserIP, Fingerprint string
}

func (s *BuntDBStorage) forTokensByIdentity(tx *buntdb.Tx,
	identity *tokenOwnerIdentity,
	iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		Platform:    utils.ShortUserAgent(identity.UserAgent),
		UserIp:      identity.UserIP,
		Fingerprint: identity.Fingerprint,
	})
	s.logger.WithField("pivot", pivot).Debugf("Iterating by identity")
	return tx.AscendEqual(indexTokens, string(pivot), iterator)
}

func (s *BuntDBStorage) forTokensByUsers(tx *buntdb.Tx, userID *common.UUID, iterator func(key, value string) bool) error {
	pivot, _ := json.Marshal(auth.StoredToken{
		UserId: userID,
	})
	s.logger.WithField("pivot", pivot).Debugf("Iterating by user")
	return tx.AscendEqual(indexUsers, string(pivot), iterator)
}

func (s *BuntDBStorage) marshalRecord(st *auth.StoredToken) string {
	ret, _ := json.Marshal(st)
	s.logger.WithField("record", st).Debugf("Marshal record")
	return string(ret)
}

func (s *BuntDBStorage) unmarshalRecord(rawRecord string) *auth.StoredToken {
	ret := new(auth.StoredToken)
	json.Unmarshal([]byte(rawRecord), ret)
	s.logger.WithField("rawRecord", rawRecord).Debugf("Unmarshal record")
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

func (s *BuntDBStorage) deleteTokenByUser(tx *buntdb.Tx, userID *common.UUID) error {
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
			return err
		}
	}
	return nil
}

func (s *BuntDBStorage) wrapTXError(err error) error {
	if _, ok := status.FromError(err); ok { // forward grpc errors
		return err
	}
	s.logger.WithError(err).Error("transaction error")
	return errStorage
}

// CreateToken creates token with parameters given in req. This operation is transactional.
func (s *BuntDBStorage) CreateToken(ctx context.Context, req *auth.CreateTokenRequest) (*auth.CreateTokenResponse, error) {
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
		userIDHash := sha256.Sum256([]byte(req.GetUserId().Value))
		logger.WithField("userIDHash", userIDHash).Debug("Issue tokens")
		accessToken, refreshToken, err = s.TokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash: hex.EncodeToString(userIDHash[:]),
			Role:       req.GetUserRole(),
		})
		if err != nil {
			s.logger.WithError(err).Error("token issue failed")
			return errTokenFactory
		}

		// store tokens
		logger.WithField("accessToken", accessToken).
			WithField("refreshToken", refreshToken).
			Debug("Store tokens")
		_, _, err = tx.Set(refreshToken.ID.Value,
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
	}, s.wrapTXError(err)
}

// CheckToken checks user token. Only access token may be checked.
// errInvalidToken will be returned if token expired, cannot be parsed or it is not access token
// errTokenNotOwnedBySender returned if user IP or fingerprint not matches with recorded at token creation.
func (s *BuntDBStorage) CheckToken(ctx context.Context, req *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Validating token")
	valid, err := s.TokenFactory.ValidateToken(req.GetAccessToken())
	if err != nil || !valid.Valid || valid.Kind != token.KindAccess {
		return nil, errInvalidToken
	}
	var rec *auth.StoredToken
	logger.Debugf("Find record in storage")
	err = s.db.View(func(tx *buntdb.Tx) error {
		rawRec, getErr := tx.Get(valid.ID.Value)
		if getErr != nil {
			return getErr
		}
		rec = s.unmarshalRecord(rawRec)
		return nil
	})
	if txErr := s.wrapTXError(err); txErr != nil {
		return nil, err
	}
	if rec.UserIp != req.GetUserIp() || rec.Fingerprint != req.GetFingerPrint() {
		return nil, errTokenNotOwnedBySender
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

// ExtendToken exchanges valid refresh token to new access and refresh tokens.
func (s *BuntDBStorage) ExtendToken(ctx context.Context, req *auth.ExtendTokenRequest) (*auth.ExtendTokenResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Info("Extend token")

	// validate received token
	logger.Debugf("Validate token")
	valid, err := s.TokenFactory.ValidateToken(req.GetRefreshToken())
	if err != nil {
		s.logger.WithError(err).Info("malformed token received")
		return nil, errInvalidToken
	}
	if !valid.Valid || valid.Kind != token.KindRefresh {
		return nil, errInvalidToken
	}

	var accessToken, refreshToken *token.IssuedToken
	err = s.db.Update(func(tx *buntdb.Tx) error {
		// identify token owner
		logger.Debugf("Identify token owner")
		rawRec, txErr := tx.Get(valid.ID.Value)
		if txErr != nil {
			return txErr
		}
		rec := s.unmarshalRecord(rawRec)
		if rec.Fingerprint != req.GetFingerprint() {
			return errTokenNotOwnedBySender
		}

		// remove old tokens
		logger.WithField("record", rec).Debugf("Delete old token")
		if delErr := s.deleteTokenByIdentity(tx, &tokenOwnerIdentity{
			UserAgent:   rec.UserAgent,
			UserIP:      rec.UserIp,
			Fingerprint: rec.Fingerprint,
		}); delErr != nil {
			return delErr
		}

		// issue new tokens
		userIDHash := sha256.Sum256([]byte(rec.UserId.Value))
		logger.WithField("userIDHash", userIDHash).Debug("Issue new tokens")
		accessToken, refreshToken, txErr = s.TokenFactory.IssueTokens(token.ExtensionFields{
			UserIDHash: hex.EncodeToString(userIDHash[:]),
			Role:       rec.UserRole,
		})
		if txErr != nil {
			s.logger.WithError(err).Error("token issue failed")
			return errTokenFactory
		}
		refreshTokenRecord := *rec
		refreshTokenRecord.TokenId = refreshToken.ID

		// store new tokens
		logger.WithField("record", refreshTokenRecord).Debug("Store new tokens")
		_, _, txErr = tx.Set(refreshToken.ID.Value,
			s.marshalRecord(&refreshTokenRecord),
			&buntdb.SetOptions{
				Expires: true,
				TTL:     refreshToken.LifeTime,
			})
		return txErr
	})

	return &auth.ExtendTokenResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, s.wrapTXError(err)
}

// UpdateAccess currently not designed
func (*BuntDBStorage) UpdateAccess(context.Context, *auth.UpdateAccessRequest) (*empty.Empty, error) {
	panic("implement me")
}

// GetUserTokens returns meta information (token id, user agent, user IP) for user
func (s *BuntDBStorage) GetUserTokens(ctx context.Context, req *auth.GetUserTokensRequest) (*auth.GetUserTokensResponse, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Get user tokens")
	resp := new(auth.GetUserTokensResponse)
	err := s.db.View(func(tx *buntdb.Tx) error {
		return s.forTokensByUsers(tx, req.GetUserId(), func(key, value string) bool {
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
	return resp, s.wrapTXError(err)
}

// DeleteToken deletes token for user.
// ErrTokenNotOwnerBySender returned if token owner id not matches id in request
func (s *BuntDBStorage) DeleteToken(ctx context.Context, req *auth.DeleteTokenRequest) (*empty.Empty, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Delete token")
	return new(empty.Empty), s.wrapTXError(s.db.Update(func(tx *buntdb.Tx) error {
		value, err := tx.Delete(req.GetTokenId().Value)
		if err != nil {
			return err
		}
		rec := s.unmarshalRecord(value)
		if !utils.UUIDEquals(rec.UserId, req.GetUserId()) {
			err = errTokenNotOwnedBySender
		}
		return err
	}))
}

// DeleteUserTokens deletes all user tokens
func (s *BuntDBStorage) DeleteUserTokens(ctx context.Context, req *auth.DeleteUserTokensRequest) (*empty.Empty, error) {
	logger := s.logger.WithField("request", req)

	logger.Infof("Delete user tokens")
	return new(empty.Empty), s.wrapTXError(s.db.Update(func(tx *buntdb.Tx) error {
		return s.deleteTokenByUser(tx, req.GetUserId())
	}))
}

// Close implements closer interface
func (s *BuntDBStorage) Close() error {
	s.logger.Info("Closing database")
	return s.db.Close()
}
