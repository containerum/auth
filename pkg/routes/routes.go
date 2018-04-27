package routes

import (
	"net/http"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/proto"
	"github.com/containerum/cherry/adaptors/gonic"
	"github.com/containerum/utils/httputil"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

var srv authProto.AuthServer

// SetupRoutes sets up router and services needed for server operation
func SetupRoutes(engine gin.IRouter, server authProto.AuthServer) {
	srv = server

	corsCfg := cors.DefaultConfig()
	corsCfg.AllowAllOrigins = true
	corsCfg.AddAllowHeaders(
		httputil.UserAgentXHeader,
		httputil.UserClientXHeader,
		httputil.UserIDXHeader,
		httputil.UserIPXHeader,
		httputil.UserRoleXHeader,
	)
	engine.Use(cors.New(corsCfg))

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
		//  - name: resources_accesses
		//    in: body
		//    required: true
		//    schema:
		//      type: object
		//      properties:
		//        access:
		//          $ref: '#/definitions/ResourcesAccess'
		// responses:
		//  '200':
		//    description: access and refresh tokens created
		//    schema:
		//      $ref: '#/definitions/CreateTokenResponse'
		//  default:
		//    $ref: '#/responses/error'
		token.POST("", httputil.RequireHeaders(
			autherr.ErrValidation,
			httputil.UserAgentXHeader,
			httputil.UserClientXHeader,
			httputil.UserIDXHeader,
			httputil.UserIPXHeader,
			httputil.UserRoleXHeader,
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
		//    $ref: '#/responses/error'
		token.GET("/:access_token", httputil.RequireHeaders(
			autherr.ErrValidation,
			httputil.UserAgentXHeader,
			httputil.UserClientXHeader,
			httputil.UserIPXHeader,
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
		//    $ref: '#/responses/error'
		token.GET("",
			httputil.RequireHeaders(autherr.ErrValidation, httputil.UserIDXHeader),
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
		//    $ref: '#/responses/error'
		token.PUT("/:refresh_token",
			httputil.RequireHeaders(autherr.ErrValidation, httputil.UserClientXHeader),
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
		//    $ref: '#/responses/error'
		token.DELETE("/:token_id",
			httputil.RequireHeaders(autherr.ErrValidation, httputil.UserIDXHeader),
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
		//    $ref: '#/responses/error'
		byID.GET("/access/:token_id",
			httputil.RequireHeaders(autherr.ErrValidation, httputil.UserRoleXHeader),
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
		//    $ref: '#/responses/error'
		user.DELETE("/:user_id/tokens", deleteUserTokensHandler)
	}

	// swagger:operation PUT /access UpdateUserAccesses
	// Rewrite user-namespace and user-volume accesses in DB for each user.
	//
	// ---
	// x-method-visibility: private
	// parameters:
	//  - name: body
	//    in: body
	//    schema:
	//      $ref: '#/definitions/UpdateAccessRequest'
	// responses:
	//  '200':
	//    description: accesses updated
	//  default:
	//    $ref: '#/responses/error'
	engine.PUT("/access", updateAccessesHandler)
}

func createTokenHandler(ctx *gin.Context) {
	req := &authProto.CreateTokenRequest{
		UserAgent:   httputil.MustGetUserAgent(ctx.Request.Context()),
		Fingerprint: httputil.MustGetFingerprint(ctx.Request.Context()),
		UserId:      httputil.MustGetUserID(ctx.Request.Context()),
		UserIp:      httputil.MustGetClientIP(ctx.Request.Context()),
		UserRole:    httputil.MustGetUserRole(ctx.Request.Context()),
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

	ctx.Set(httputil.UserIDXHeader, resp.GetUserId())
	ctx.Set(httputil.UserRoleXHeader, resp.GetUserRole())
	ctx.Set(httputil.TokenIDXHeader, resp.GetTokenId())

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

func updateAccessesHandler(ctx *gin.Context) {
	var req authProto.UpdateAccessRequest

	if err := ctx.ShouldBindWith(&req, binding.JSON); err != nil {
		ctx.AbortWithStatusJSON(badRequest(err))
		return
	}

	if _, err := srv.UpdateAccess(ctx, &req); err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}
