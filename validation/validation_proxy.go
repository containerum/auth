package validation

import (
	"context"

	"git.containerum.net/ch/grpc-proto-files/auth"
	"git.containerum.net/ch/kube-client/pkg/cherry"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/cherrylog"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
)

// ServerWrapper is a special wrapper to Validate incoming requests and then call "upstream"
type ServerWrapper struct {
	upstream      auth.AuthServer
	log           *cherrylog.LogrusAdapter
	validator     *validator.Validate
	validationErr func() *cherry.Err
}

// NewServerWrapper constructs ServerWrapper
func NewServerWrapper(upstream auth.AuthServer, validator *validator.Validate, validationErr func() *cherry.Err) auth.AuthServer {
	return &ServerWrapper{
		upstream:      upstream,
		log:           cherrylog.NewLogrusAdapter(logrus.WithField("component", "validation_proxy")),
		validator:     validator,
		validationErr: validationErr,
	}
}

func (v *ServerWrapper) validateStruct(ctx context.Context, req interface{}) error {
	v.log.Debugf("validating struct %T", req)
	err := v.validator.StructCtx(ctx, req)
	if err != nil {
		if validatorErrs, ok := err.(validator.ValidationErrors); ok {
			ret := v.validationErr()
			// TODO: maybe return "json" field name
			for fieldName, fieldErr := range validatorErrs {
				if fieldErr == nil {
					continue
				}
				ret.AddDetailF("field %s: validation failed for %s tag", fieldName, fieldErr.Tag)
			}
			err = ret
		} else {
			err = v.validationErr().AddDetailsErr(err).Log(err, v.log)
		}
	}
	return err
}

// CreateToken performs request validation and calls underlying method
func (v *ServerWrapper) CreateToken(ctx context.Context, req *auth.CreateTokenRequest) (*auth.CreateTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.CreateToken(ctx, req)
}

// CheckToken performs request validation and calls underlying method
func (v *ServerWrapper) CheckToken(ctx context.Context, req *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.CheckToken(ctx, req)
}

// ExtendToken performs request validation and calls underlying method
func (v *ServerWrapper) ExtendToken(ctx context.Context, req *auth.ExtendTokenRequest) (*auth.ExtendTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.ExtendToken(ctx, req)
}

// UpdateAccess performs request validation and calls underlying method
func (v *ServerWrapper) UpdateAccess(ctx context.Context, req *auth.UpdateAccessRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.UpdateAccess(ctx, req)
}

// GetUserTokens performs request validation and calls underlying method
func (v *ServerWrapper) GetUserTokens(ctx context.Context, req *auth.GetUserTokensRequest) (*auth.GetUserTokensResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.GetUserTokens(ctx, req)
}

// DeleteToken performs request validation and calls underlying method
func (v *ServerWrapper) DeleteToken(ctx context.Context, req *auth.DeleteTokenRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteToken(ctx, req)
}

// DeleteUserTokens performs request validation and calls underlying method
func (v *ServerWrapper) DeleteUserTokens(ctx context.Context, req *auth.DeleteUserTokensRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteUserTokens(ctx, req)
}
