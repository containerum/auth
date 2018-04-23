package routes

import (
	"net/http"

	"git.containerum.net/ch/auth/proto"
	umtypes "git.containerum.net/ch/json-types/user-manager"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/gonic"
	"git.containerum.net/ch/kube-client/pkg/cherry/auth"
	"git.containerum.net/ch/utils/httputil"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

var srv authProto.AuthServer

// SetupRoutes sets up router and services needed for server operation
func SetupRoutes(engine gin.IRouter, server authProto.AuthServer) {
	srv = server

	engine = engine.Group("/")
	engine.Use(httputil.PrepareContext)

	token := engine.Group("/token")
	{
		// swagger:operation POST /token CreateToken
		// Creates token for user.
		//
		// ---
		// x-method-visibility: private
		// parameters:
		//  - $ref: '#/parameters/UserAgentHeader'
		//  - $ref: '#/parameters/FingerprintHeader'
		//  - $ref: '#/parameters/UserIDHeader'
		//  - $ref: '#/parameters/UserRoleHeader'
		//  - $ref: '#/parameters/ClientIPHeader'
		//  - $ref: '#/parameters/PartTokenIDHeader'
		// responses:
		//  '200':
		//    description: access and refresh tokens created
		//    schema:
		//      $ref: '#/definitions/CreateTokenResponse'
		//  default:
		//    description: error
		token.POST("", httputil.RequireHeaders(
			autherr.ErrValidation,
			umtypes.UserAgentHeader,
			umtypes.FingerprintHeader,
			umtypes.UserIDHeader,
			umtypes.ClientIPHeader,
			umtypes.UserRoleHeader,
		), createTokenHandler)

		// swagger:operation GET /token/{access_token} CheckToken
		// Checks token and returns resources accesses.
		//
		// ---
		// x-method-visibility: private
		// parameters:
		//  - $ref: '#/parameters/UserAgentHeader'
		//  - $ref: '#/parameters/FingerprintHeader'
		//  - $ref: '#/parameters/ClientIPHeader'
		//  - name: access_token
		//    in: path
		//    type: string
		//    required: true
		// responses:
		//  '200':
		//    description: token valid
		//    schema:
		//      type: object
		//      properties:
		//        access:
		//          $ref: '#/definitions/ResourcesAccess'
		//  default:
		//    description: error
		token.GET("/:access_token", httputil.RequireHeaders(
			autherr.ErrValidation,
			umtypes.UserAgentHeader,
			umtypes.FingerprintHeader,
			umtypes.ClientIPHeader,
		), checkTokenHandler)

		// swagger:operation GET /token GetUserTokens
		// Get user tokens.
		//
		// ---
		// x-method-visibility: public
		// x-authorization-required: true
		// parameters:
		//  - $ref: '#/parameters/UserIDHeader'
		// responses:
		//  '200':
		//    description: user tokens
		//    schema:
		//      $ref: '#/definitions/GetUserTokensResponse'
		//  default:
		//    description: error
		token.GET("",
			httputil.RequireHeaders(autherr.ErrValidation, umtypes.UserIDHeader),
			getUserTokensHandler)

		// swagger:operation PUT /token/{refresh_token} ExtendToken
		// Get new access/refresh token pair using refresh token.
		//
		// ---
		// x-method-visibility: public
		// x-authorization-required: false
		// parameters:
		//  - $ref: '#/parameters/FingerprintHeader'
		//  - name: refresh_token
		//    description: valid refresh token
		//    in: path
		//    type: string
		//    required: true
		// responses:
		//  '200':
		//    description: access and refresh tokens extended
		//    schema:
		//      $ref: '#/definitions/ExtendTokenResponse'
		//  default:
		//    description: error
		token.PUT("/:refresh_token",
			httputil.RequireHeaders(autherr.ErrValidation, umtypes.FingerprintHeader),
			extendTokenHandler)

		// swagger:operation DELETE /token/{token_id} DeleteTokenByID
		// Delete token (record) by id.
		//
		// ---
		// x-method-visibility: public
		// x-authorization-required: true
		// parameters:
		//  - $ref: '#/parameters/UserIDHeader'
		//  - name: token_id
		//    in: path
		//    type: string
		//    format: uuid
		//    required: true
		// responses:
		//  '200':
		//    description: token deleted
		//  default:
		//    description: error
		token.DELETE("/:token_id",
			httputil.RequireHeaders(autherr.ErrValidation, umtypes.UserIDHeader),
			deleteTokenByIDHandler)
	}

	byID := engine.Group("/byid/")
	{
		// swagger:operation GET /byid/access/{token_id} GetAccessTokenByID
		// Get access token by ID.
		//
		// ---
		// parameters:
		//  - $ref: '#/parameters/UserRoleHeader'
		//  - name: token_id
		//    in: path
		//    type: string
		//    format: uuid
		//    required: true
		// responses:
		//  '200':
		//    description: access token
		//    schema:
		//     $ref: '#/definitions/AccessTokenByIDResponse'
		//  default:
		//    description: error
		byID.GET("/access/:token_id",
			httputil.RequireHeaders(autherr.ErrValidation, umtypes.UserRoleHeader),
			getAccessTokenByIDHandler,
		)
	}

	user := engine.Group("/user")
	{
		// swagger:operation DELETE /user/{user_id}/tokens DeleteUserTokens
		// Delete user (refresh) tokens. Also makes access tokens invalid.
		//
		// ---
		// x-method-visibility: private
		// parameters:
		//  - name: user_id
		//    in: path
		//    type: string
		//    format: uuid
		//    required: true
		// responses:
		//  '200':
		//    description: tokens deleted
		//  default:
		//    description: error
		user.DELETE("/:user_id/tokens", deleteUserTokensHandler)
	}
}

func createTokenHandler(ctx *gin.Context) {
	req := &authProto.CreateTokenRequest{
		UserAgent:   httputil.MustGetUserAgent(ctx.Request.Context()),
		Fingerprint: httputil.MustGetFingerprint(ctx.Request.Context()),
		UserId:      httputil.MustGetUserID(ctx.Request.Context()),
		UserIp:      httputil.MustGetClientIP(ctx.Request.Context()),
		UserRole:    httputil.MustGetUserRole(ctx.Request.Context()),
	}
	ptID, ptIDExist := httputil.GetPartTokenID(ctx.Request.Context())
	if ptIDExist {
		req.PartTokenId = ptID
	}

	var access struct {
		Access *authProto.ResourcesAccess `json:"access" binding:"required"`
	}

	if err := ctx.ShouldBindWith(&access, binding.JSON); err != nil {
		gonic.Gonic(autherr.ErrValidation().AddDetailsErr(err), ctx)
		return
	}

	req.Access = access.Access

	resp, err := srv.CreateToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func checkTokenHandler(ctx *gin.Context) {
	req := &authProto.CheckTokenRequest{
		AccessToken: ctx.Param("access_token"),
		UserAgent:   httputil.MustGetUserAgent(ctx.Request.Context()),
		FingerPrint: httputil.MustGetFingerprint(ctx.Request.Context()),
		UserIp:      httputil.MustGetClientIP(ctx.Request.Context()),
	}

	resp, err := srv.CheckToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Set(umtypes.UserIDHeader, resp.GetUserId())
	ctx.Set(umtypes.UserRoleHeader, resp.GetUserRole())
	ctx.Set(umtypes.TokenIDHeader, resp.GetTokenId())
	if resp.PartTokenId != "" {
		ctx.Set(umtypes.PartTokenIDHeader, resp.GetPartTokenId())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access": resp.GetAccess(),
	})
}

func extendTokenHandler(ctx *gin.Context) {
	req := &authProto.ExtendTokenRequest{
		RefreshToken: ctx.Param("refresh_token"),
		Fingerprint:  httputil.MustGetFingerprint(ctx.Request.Context()),
	}

	resp, err := srv.ExtendToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func getUserTokensHandler(ctx *gin.Context) {
	req := &authProto.GetUserTokensRequest{
		UserId: httputil.MustGetUserID(ctx.Request.Context()),
	}

	resp, err := srv.GetUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func deleteTokenByIDHandler(ctx *gin.Context) {
	req := &authProto.DeleteTokenRequest{
		TokenId: ctx.Param("token_id"),
		UserId:  httputil.MustGetUserID(ctx.Request.Context()),
	}

	_, err := srv.DeleteToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func deleteUserTokensHandler(ctx *gin.Context) {
	req := &authProto.DeleteUserTokensRequest{
		UserId: ctx.Param("user_id"),
	}

	_, err := srv.DeleteUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func getAccessTokenByIDHandler(ctx *gin.Context) {
	req := &authProto.AccessTokenByIDRequest{
		TokenId: ctx.Param("token_id"),
	}

	resp, err := srv.AccessTokenByID(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}
