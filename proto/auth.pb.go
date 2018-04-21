// Code generated by protoc-gen-go. DO NOT EDIT.
// source: auth.proto

/*
Package authProto is a generated protocol buffer package.

It is generated from these files:
	auth.proto
	auth_types.proto

It has these top-level messages:
	CreateTokenRequest
	CreateTokenResponse
	CheckTokenRequest
	CheckTokenResponse
	ExtendTokenRequest
	ExtendTokenResponse
	UpdateAccessRequestElement
	UpdateAccessRequest
	GetUserTokensRequest
	GetUserTokensResponse
	DeleteTokenRequest
	DeleteUserTokensRequest
	AccessTokenByIDRequest
	AccessTokenByIDResponse
	StoredToken
	AccessObject
	ResourcesAccess
	StoredTokenForUser
*/
package authProto

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf2 "github.com/golang/protobuf/ptypes/empty"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// swagger:ignore
type CreateTokenRequest struct {
	UserAgent   string `protobuf:"bytes,1,opt,name=user_agent,json=userAgent" json:"user_agent,omitempty"`
	Fingerprint string `protobuf:"bytes,2,opt,name=fingerprint" json:"fingerprint,omitempty"`
	// @inject_tag: binding:"uuid"
	UserId string `protobuf:"bytes,3,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
	// @inject_tag: binding:"ip"
	UserIp   string           `protobuf:"bytes,4,opt,name=user_ip,json=userIp" json:"user_ip,omitempty" binding:"ip"`
	UserRole string           `protobuf:"bytes,5,opt,name=user_role,json=userRole" json:"user_role,omitempty"`
	RwAccess bool             `protobuf:"varint,6,opt,name=rw_access,json=rwAccess" json:"rw_access,omitempty"`
	Access   *ResourcesAccess `protobuf:"bytes,7,opt,name=access" json:"access,omitempty"`
	// @inject_tag: binding:"uuid"
	PartTokenId string `protobuf:"bytes,8,opt,name=part_token_id,json=partTokenId" json:"part_token_id,omitempty" binding:"uuid"`
}

func (m *CreateTokenRequest) Reset()                    { *m = CreateTokenRequest{} }
func (m *CreateTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateTokenRequest) ProtoMessage()               {}
func (*CreateTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *CreateTokenRequest) GetUserAgent() string {
	if m != nil {
		return m.UserAgent
	}
	return ""
}

func (m *CreateTokenRequest) GetFingerprint() string {
	if m != nil {
		return m.Fingerprint
	}
	return ""
}

func (m *CreateTokenRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *CreateTokenRequest) GetUserIp() string {
	if m != nil {
		return m.UserIp
	}
	return ""
}

func (m *CreateTokenRequest) GetUserRole() string {
	if m != nil {
		return m.UserRole
	}
	return ""
}

func (m *CreateTokenRequest) GetRwAccess() bool {
	if m != nil {
		return m.RwAccess
	}
	return false
}

func (m *CreateTokenRequest) GetAccess() *ResourcesAccess {
	if m != nil {
		return m.Access
	}
	return nil
}

func (m *CreateTokenRequest) GetPartTokenId() string {
	if m != nil {
		return m.PartTokenId
	}
	return ""
}

// CreateTokenResponse contains access and refresh token.
//
// swagger:model
type CreateTokenResponse struct {
	AccessToken  string `protobuf:"bytes,1,opt,name=access_token,json=accessToken" json:"access_token,omitempty"`
	RefreshToken string `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken" json:"refresh_token,omitempty"`
}

func (m *CreateTokenResponse) Reset()                    { *m = CreateTokenResponse{} }
func (m *CreateTokenResponse) String() string            { return proto.CompactTextString(m) }
func (*CreateTokenResponse) ProtoMessage()               {}
func (*CreateTokenResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *CreateTokenResponse) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *CreateTokenResponse) GetRefreshToken() string {
	if m != nil {
		return m.RefreshToken
	}
	return ""
}

// swagger:ignore
type CheckTokenRequest struct {
	AccessToken string `protobuf:"bytes,1,opt,name=access_token,json=accessToken" json:"access_token,omitempty"`
	UserAgent   string `protobuf:"bytes,2,opt,name=user_agent,json=userAgent" json:"user_agent,omitempty"`
	FingerPrint string `protobuf:"bytes,3,opt,name=finger_print,json=fingerPrint" json:"finger_print,omitempty"`
	// @inject_tag: binding:"ip"
	UserIp string `protobuf:"bytes,4,opt,name=user_ip,json=userIp" json:"user_ip,omitempty" binding:"ip"`
}

func (m *CheckTokenRequest) Reset()                    { *m = CheckTokenRequest{} }
func (m *CheckTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*CheckTokenRequest) ProtoMessage()               {}
func (*CheckTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *CheckTokenRequest) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *CheckTokenRequest) GetUserAgent() string {
	if m != nil {
		return m.UserAgent
	}
	return ""
}

func (m *CheckTokenRequest) GetFingerPrint() string {
	if m != nil {
		return m.FingerPrint
	}
	return ""
}

func (m *CheckTokenRequest) GetUserIp() string {
	if m != nil {
		return m.UserIp
	}
	return ""
}

// swagger:ignore
type CheckTokenResponse struct {
	Access *ResourcesAccess `protobuf:"bytes,1,opt,name=access" json:"access,omitempty"`
	// @inject_tag: binding:"uuid"
	UserId   string `protobuf:"bytes,2,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
	UserRole string `protobuf:"bytes,3,opt,name=user_role,json=userRole" json:"user_role,omitempty"`
	// @inject_tag: binding:"uuid"
	TokenId string `protobuf:"bytes,4,opt,name=token_id,json=tokenId" json:"token_id,omitempty" binding:"uuid"`
	// @inject_tag: binding:"uuid"
	PartTokenId string `protobuf:"bytes,5,opt,name=part_token_id,json=partTokenId" json:"part_token_id,omitempty" binding:"uuid"`
}

func (m *CheckTokenResponse) Reset()                    { *m = CheckTokenResponse{} }
func (m *CheckTokenResponse) String() string            { return proto.CompactTextString(m) }
func (*CheckTokenResponse) ProtoMessage()               {}
func (*CheckTokenResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *CheckTokenResponse) GetAccess() *ResourcesAccess {
	if m != nil {
		return m.Access
	}
	return nil
}

func (m *CheckTokenResponse) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *CheckTokenResponse) GetUserRole() string {
	if m != nil {
		return m.UserRole
	}
	return ""
}

func (m *CheckTokenResponse) GetTokenId() string {
	if m != nil {
		return m.TokenId
	}
	return ""
}

func (m *CheckTokenResponse) GetPartTokenId() string {
	if m != nil {
		return m.PartTokenId
	}
	return ""
}

// swagger:ignore
type ExtendTokenRequest struct {
	RefreshToken string `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken" json:"refresh_token,omitempty"`
	Fingerprint  string `protobuf:"bytes,2,opt,name=fingerprint" json:"fingerprint,omitempty"`
}

func (m *ExtendTokenRequest) Reset()                    { *m = ExtendTokenRequest{} }
func (m *ExtendTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*ExtendTokenRequest) ProtoMessage()               {}
func (*ExtendTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *ExtendTokenRequest) GetRefreshToken() string {
	if m != nil {
		return m.RefreshToken
	}
	return ""
}

func (m *ExtendTokenRequest) GetFingerprint() string {
	if m != nil {
		return m.Fingerprint
	}
	return ""
}

// ExtendTokenResponse contains new access and refresh tokens
//
// swagger:model
type ExtendTokenResponse struct {
	AccessToken  string `protobuf:"bytes,1,opt,name=access_token,json=accessToken" json:"access_token,omitempty"`
	RefreshToken string `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken" json:"refresh_token,omitempty"`
}

func (m *ExtendTokenResponse) Reset()                    { *m = ExtendTokenResponse{} }
func (m *ExtendTokenResponse) String() string            { return proto.CompactTextString(m) }
func (*ExtendTokenResponse) ProtoMessage()               {}
func (*ExtendTokenResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ExtendTokenResponse) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *ExtendTokenResponse) GetRefreshToken() string {
	if m != nil {
		return m.RefreshToken
	}
	return ""
}

// swagger:ignore
type UpdateAccessRequestElement struct {
	// @inject_tag: binding:"uuid"
	UserId string           `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
	Access *ResourcesAccess `protobuf:"bytes,2,opt,name=access" json:"access,omitempty"`
}

func (m *UpdateAccessRequestElement) Reset()                    { *m = UpdateAccessRequestElement{} }
func (m *UpdateAccessRequestElement) String() string            { return proto.CompactTextString(m) }
func (*UpdateAccessRequestElement) ProtoMessage()               {}
func (*UpdateAccessRequestElement) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *UpdateAccessRequestElement) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *UpdateAccessRequestElement) GetAccess() *ResourcesAccess {
	if m != nil {
		return m.Access
	}
	return nil
}

// swagger:ignore
type UpdateAccessRequest struct {
	Users []*UpdateAccessRequestElement `protobuf:"bytes,1,rep,name=users" json:"users,omitempty"`
}

func (m *UpdateAccessRequest) Reset()                    { *m = UpdateAccessRequest{} }
func (m *UpdateAccessRequest) String() string            { return proto.CompactTextString(m) }
func (*UpdateAccessRequest) ProtoMessage()               {}
func (*UpdateAccessRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *UpdateAccessRequest) GetUsers() []*UpdateAccessRequestElement {
	if m != nil {
		return m.Users
	}
	return nil
}

// swagger:ignore
type GetUserTokensRequest struct {
	// @inject_tag: binding:"uuid"
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
}

func (m *GetUserTokensRequest) Reset()                    { *m = GetUserTokensRequest{} }
func (m *GetUserTokensRequest) String() string            { return proto.CompactTextString(m) }
func (*GetUserTokensRequest) ProtoMessage()               {}
func (*GetUserTokensRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *GetUserTokensRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

// GetUserTokensResponse contains user tokens
//
// swagger:model
type GetUserTokensResponse struct {
	Tokens []*StoredTokenForUser `protobuf:"bytes,1,rep,name=tokens" json:"tokens,omitempty"`
}

func (m *GetUserTokensResponse) Reset()                    { *m = GetUserTokensResponse{} }
func (m *GetUserTokensResponse) String() string            { return proto.CompactTextString(m) }
func (*GetUserTokensResponse) ProtoMessage()               {}
func (*GetUserTokensResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *GetUserTokensResponse) GetTokens() []*StoredTokenForUser {
	if m != nil {
		return m.Tokens
	}
	return nil
}

// swagger:ignore
type DeleteTokenRequest struct {
	// @inject_tag: binding:"uuid"
	TokenId string `protobuf:"bytes,1,opt,name=token_id,json=tokenId" json:"token_id,omitempty" binding:"uuid"`
	// @inject_tag: binding:"uuid"
	UserId string `protobuf:"bytes,2,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
}

func (m *DeleteTokenRequest) Reset()                    { *m = DeleteTokenRequest{} }
func (m *DeleteTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*DeleteTokenRequest) ProtoMessage()               {}
func (*DeleteTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *DeleteTokenRequest) GetTokenId() string {
	if m != nil {
		return m.TokenId
	}
	return ""
}

func (m *DeleteTokenRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

// swagger:ignore
type DeleteUserTokensRequest struct {
	// @inject_tag: binding:"uuid"
	UserId string `protobuf:"bytes,1,opt,name=user_id,json=userId" json:"user_id,omitempty" binding:"uuid"`
}

func (m *DeleteUserTokensRequest) Reset()                    { *m = DeleteUserTokensRequest{} }
func (m *DeleteUserTokensRequest) String() string            { return proto.CompactTextString(m) }
func (*DeleteUserTokensRequest) ProtoMessage()               {}
func (*DeleteUserTokensRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *DeleteUserTokensRequest) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

// swagger:ignore
type AccessTokenByIDRequest struct {
	// @inject_tag: binding:"uuid"
	TokenId  string `protobuf:"bytes,1,opt,name=token_id,json=tokenId" json:"token_id,omitempty" binding:"uuid"`
	UserRole string `protobuf:"bytes,2,opt,name=user_role,json=userRole" json:"user_role,omitempty"`
}

func (m *AccessTokenByIDRequest) Reset()                    { *m = AccessTokenByIDRequest{} }
func (m *AccessTokenByIDRequest) String() string            { return proto.CompactTextString(m) }
func (*AccessTokenByIDRequest) ProtoMessage()               {}
func (*AccessTokenByIDRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *AccessTokenByIDRequest) GetTokenId() string {
	if m != nil {
		return m.TokenId
	}
	return ""
}

func (m *AccessTokenByIDRequest) GetUserRole() string {
	if m != nil {
		return m.UserRole
	}
	return ""
}

// swagger:ignore
type AccessTokenByIDResponse struct {
	AccessToken string `protobuf:"bytes,1,opt,name=access_token,json=accessToken" json:"access_token,omitempty"`
}

func (m *AccessTokenByIDResponse) Reset()                    { *m = AccessTokenByIDResponse{} }
func (m *AccessTokenByIDResponse) String() string            { return proto.CompactTextString(m) }
func (*AccessTokenByIDResponse) ProtoMessage()               {}
func (*AccessTokenByIDResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

func (m *AccessTokenByIDResponse) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func init() {
	proto.RegisterType((*CreateTokenRequest)(nil), "CreateTokenRequest")
	proto.RegisterType((*CreateTokenResponse)(nil), "CreateTokenResponse")
	proto.RegisterType((*CheckTokenRequest)(nil), "CheckTokenRequest")
	proto.RegisterType((*CheckTokenResponse)(nil), "CheckTokenResponse")
	proto.RegisterType((*ExtendTokenRequest)(nil), "ExtendTokenRequest")
	proto.RegisterType((*ExtendTokenResponse)(nil), "ExtendTokenResponse")
	proto.RegisterType((*UpdateAccessRequestElement)(nil), "UpdateAccessRequestElement")
	proto.RegisterType((*UpdateAccessRequest)(nil), "UpdateAccessRequest")
	proto.RegisterType((*GetUserTokensRequest)(nil), "GetUserTokensRequest")
	proto.RegisterType((*GetUserTokensResponse)(nil), "GetUserTokensResponse")
	proto.RegisterType((*DeleteTokenRequest)(nil), "DeleteTokenRequest")
	proto.RegisterType((*DeleteUserTokensRequest)(nil), "DeleteUserTokensRequest")
	proto.RegisterType((*AccessTokenByIDRequest)(nil), "AccessTokenByIDRequest")
	proto.RegisterType((*AccessTokenByIDResponse)(nil), "AccessTokenByIDResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Auth service

type AuthClient interface {
	CreateToken(ctx context.Context, in *CreateTokenRequest, opts ...grpc.CallOption) (*CreateTokenResponse, error)
	CheckToken(ctx context.Context, in *CheckTokenRequest, opts ...grpc.CallOption) (*CheckTokenResponse, error)
	ExtendToken(ctx context.Context, in *ExtendTokenRequest, opts ...grpc.CallOption) (*ExtendTokenResponse, error)
	UpdateAccess(ctx context.Context, in *UpdateAccessRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error)
	GetUserTokens(ctx context.Context, in *GetUserTokensRequest, opts ...grpc.CallOption) (*GetUserTokensResponse, error)
	DeleteToken(ctx context.Context, in *DeleteTokenRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error)
	DeleteUserTokens(ctx context.Context, in *DeleteUserTokensRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error)
	AccessTokenByID(ctx context.Context, in *AccessTokenByIDRequest, opts ...grpc.CallOption) (*AccessTokenByIDResponse, error)
}

type authClient struct {
	cc *grpc.ClientConn
}

func NewAuthClient(cc *grpc.ClientConn) AuthClient {
	return &authClient{cc}
}

func (c *authClient) CreateToken(ctx context.Context, in *CreateTokenRequest, opts ...grpc.CallOption) (*CreateTokenResponse, error) {
	out := new(CreateTokenResponse)
	err := grpc.Invoke(ctx, "/Auth/CreateToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) CheckToken(ctx context.Context, in *CheckTokenRequest, opts ...grpc.CallOption) (*CheckTokenResponse, error) {
	out := new(CheckTokenResponse)
	err := grpc.Invoke(ctx, "/Auth/CheckToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) ExtendToken(ctx context.Context, in *ExtendTokenRequest, opts ...grpc.CallOption) (*ExtendTokenResponse, error) {
	out := new(ExtendTokenResponse)
	err := grpc.Invoke(ctx, "/Auth/ExtendToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) UpdateAccess(ctx context.Context, in *UpdateAccessRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error) {
	out := new(google_protobuf2.Empty)
	err := grpc.Invoke(ctx, "/Auth/UpdateAccess", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) GetUserTokens(ctx context.Context, in *GetUserTokensRequest, opts ...grpc.CallOption) (*GetUserTokensResponse, error) {
	out := new(GetUserTokensResponse)
	err := grpc.Invoke(ctx, "/Auth/GetUserTokens", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) DeleteToken(ctx context.Context, in *DeleteTokenRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error) {
	out := new(google_protobuf2.Empty)
	err := grpc.Invoke(ctx, "/Auth/DeleteToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) DeleteUserTokens(ctx context.Context, in *DeleteUserTokensRequest, opts ...grpc.CallOption) (*google_protobuf2.Empty, error) {
	out := new(google_protobuf2.Empty)
	err := grpc.Invoke(ctx, "/Auth/DeleteUserTokens", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authClient) AccessTokenByID(ctx context.Context, in *AccessTokenByIDRequest, opts ...grpc.CallOption) (*AccessTokenByIDResponse, error) {
	out := new(AccessTokenByIDResponse)
	err := grpc.Invoke(ctx, "/Auth/AccessTokenByID", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Auth service

type AuthServer interface {
	CreateToken(context.Context, *CreateTokenRequest) (*CreateTokenResponse, error)
	CheckToken(context.Context, *CheckTokenRequest) (*CheckTokenResponse, error)
	ExtendToken(context.Context, *ExtendTokenRequest) (*ExtendTokenResponse, error)
	UpdateAccess(context.Context, *UpdateAccessRequest) (*google_protobuf2.Empty, error)
	GetUserTokens(context.Context, *GetUserTokensRequest) (*GetUserTokensResponse, error)
	DeleteToken(context.Context, *DeleteTokenRequest) (*google_protobuf2.Empty, error)
	DeleteUserTokens(context.Context, *DeleteUserTokensRequest) (*google_protobuf2.Empty, error)
	AccessTokenByID(context.Context, *AccessTokenByIDRequest) (*AccessTokenByIDResponse, error)
}

func RegisterAuthServer(s *grpc.Server, srv AuthServer) {
	s.RegisterService(&_Auth_serviceDesc, srv)
}

func _Auth_CreateToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).CreateToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/CreateToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).CreateToken(ctx, req.(*CreateTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_CheckToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).CheckToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/CheckToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).CheckToken(ctx, req.(*CheckTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_ExtendToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExtendTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).ExtendToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/ExtendToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).ExtendToken(ctx, req.(*ExtendTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_UpdateAccess_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAccessRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).UpdateAccess(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/UpdateAccess",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).UpdateAccess(ctx, req.(*UpdateAccessRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_GetUserTokens_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserTokensRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).GetUserTokens(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/GetUserTokens",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).GetUserTokens(ctx, req.(*GetUserTokensRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_DeleteToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).DeleteToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/DeleteToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).DeleteToken(ctx, req.(*DeleteTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_DeleteUserTokens_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserTokensRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).DeleteUserTokens(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/DeleteUserTokens",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).DeleteUserTokens(ctx, req.(*DeleteUserTokensRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auth_AccessTokenByID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AccessTokenByIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServer).AccessTokenByID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Auth/AccessTokenByID",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServer).AccessTokenByID(ctx, req.(*AccessTokenByIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Auth_serviceDesc = grpc.ServiceDesc{
	ServiceName: "Auth",
	HandlerType: (*AuthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateToken",
			Handler:    _Auth_CreateToken_Handler,
		},
		{
			MethodName: "CheckToken",
			Handler:    _Auth_CheckToken_Handler,
		},
		{
			MethodName: "ExtendToken",
			Handler:    _Auth_ExtendToken_Handler,
		},
		{
			MethodName: "UpdateAccess",
			Handler:    _Auth_UpdateAccess_Handler,
		},
		{
			MethodName: "GetUserTokens",
			Handler:    _Auth_GetUserTokens_Handler,
		},
		{
			MethodName: "DeleteToken",
			Handler:    _Auth_DeleteToken_Handler,
		},
		{
			MethodName: "DeleteUserTokens",
			Handler:    _Auth_DeleteUserTokens_Handler,
		},
		{
			MethodName: "AccessTokenByID",
			Handler:    _Auth_AccessTokenByID_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "auth.proto",
}

func init() { proto.RegisterFile("auth.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 695 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0x5f, 0x4f, 0x13, 0x41,
	0x10, 0xef, 0xb5, 0x50, 0xca, 0xb4, 0x44, 0x9c, 0x16, 0x7a, 0x1e, 0x31, 0x29, 0xeb, 0x4b, 0x13,
	0x93, 0x25, 0xd6, 0x07, 0x13, 0x43, 0x8c, 0xe5, 0x9f, 0xf0, 0x46, 0x4e, 0x79, 0xd1, 0x98, 0xa6,
	0xb6, 0x43, 0x4b, 0x28, 0xbd, 0x73, 0x6f, 0x1b, 0xe4, 0x13, 0xf8, 0x68, 0xfc, 0x2c, 0x7e, 0x41,
	0xb3, 0xbb, 0x07, 0xbd, 0xbd, 0xbb, 0x02, 0x26, 0xbe, 0xdd, 0xcd, 0xcc, 0xce, 0xcc, 0xfe, 0x7e,
	0xbf, 0x99, 0x05, 0xe8, 0xcf, 0xe4, 0x98, 0x87, 0x22, 0x90, 0x81, 0xb7, 0xae, 0xbe, 0x7b, 0xf2,
	0x26, 0xa4, 0x28, 0xb6, 0x6c, 0x8d, 0x82, 0x60, 0x34, 0xa1, 0x1d, 0xfd, 0xf7, 0x6d, 0x76, 0xbe,
	0x43, 0x57, 0xa1, 0xbc, 0x31, 0x4e, 0xf6, 0xab, 0x08, 0xb8, 0x2f, 0xa8, 0x2f, 0xe9, 0x53, 0x70,
	0x49, 0x53, 0x9f, 0xbe, 0xcf, 0x28, 0x92, 0xf8, 0x1c, 0x60, 0x16, 0x91, 0xe8, 0xf5, 0x47, 0x34,
	0x95, 0xae, 0xd3, 0x72, 0xda, 0xab, 0xfe, 0xaa, 0xb2, 0x74, 0x95, 0x01, 0x5b, 0x50, 0x3d, 0xbf,
	0x98, 0x8e, 0x48, 0x84, 0xe2, 0x62, 0x2a, 0xdd, 0xa2, 0xf6, 0x27, 0x4d, 0xd8, 0x84, 0x15, 0x9d,
	0xe0, 0x62, 0xe8, 0x96, 0xb4, 0xb7, 0xac, 0x7e, 0x4f, 0x86, 0x73, 0x47, 0xe8, 0x2e, 0x25, 0x1c,
	0x21, 0x6e, 0x81, 0x2e, 0xd0, 0x13, 0xc1, 0x84, 0xdc, 0x65, 0xed, 0xaa, 0x28, 0x83, 0x1f, 0x4c,
	0x48, 0x39, 0xc5, 0x75, 0xaf, 0x3f, 0x18, 0x50, 0x14, 0xb9, 0xe5, 0x96, 0xd3, 0xae, 0xf8, 0x15,
	0x71, 0xdd, 0xd5, 0xff, 0xd8, 0x86, 0x72, 0xec, 0x59, 0x69, 0x39, 0xed, 0x6a, 0x67, 0x9d, 0xfb,
	0x14, 0x05, 0x33, 0x31, 0xa0, 0xc8, 0x44, 0xf8, 0xb1, 0x1f, 0x19, 0xac, 0x85, 0x7d, 0x21, 0x7b,
	0x52, 0xdd, 0x55, 0xf5, 0x56, 0x31, 0x9d, 0x2b, 0xa3, 0xbe, 0xff, 0xc9, 0x90, 0x7d, 0x85, 0xba,
	0x05, 0x48, 0x14, 0x06, 0xd3, 0x88, 0x70, 0x1b, 0x6a, 0x26, 0x89, 0x39, 0x1c, 0x63, 0x52, 0x35,
	0x36, 0x1d, 0x8a, 0x2f, 0x60, 0x4d, 0xd0, 0xb9, 0xa0, 0x68, 0x1c, 0xc7, 0x18, 0x5c, 0x6a, 0xb1,
	0x51, 0x07, 0xb1, 0xdf, 0x0e, 0x3c, 0xdd, 0x1f, 0xd3, 0xe0, 0xd2, 0xc2, 0xfb, 0x11, 0xd9, 0x6d,
	0x4a, 0x8a, 0x69, 0x4a, 0xb6, 0xa1, 0x66, 0xf0, 0xef, 0x19, 0x4e, 0x4a, 0x49, 0x4e, 0x4e, 0x6d,
	0x4e, 0x52, 0xd0, 0xb3, 0x3f, 0x0e, 0x60, 0xb2, 0xa7, 0xf8, 0xca, 0x73, 0x5c, 0x9d, 0x07, 0x70,
	0x4d, 0xb0, 0x5d, 0xb4, 0xd8, 0xb6, 0x48, 0x2d, 0xa5, 0x48, 0x7d, 0x06, 0x95, 0x3b, 0x22, 0x4c,
	0x43, 0x2b, 0xd2, 0x90, 0x90, 0x25, 0x6a, 0x39, 0x4b, 0xd4, 0x17, 0xc0, 0xc3, 0x1f, 0x92, 0xa6,
	0x43, 0x0b, 0xc9, 0x0c, 0x09, 0x4e, 0x96, 0x84, 0x87, 0xf5, 0xab, 0x54, 0x60, 0x25, 0xff, 0xcf,
	0x2a, 0xe8, 0x81, 0x77, 0x16, 0x0e, 0xfb, 0x92, 0x62, 0x20, 0x4d, 0xf3, 0x87, 0x13, 0xba, 0x22,
	0x7b, 0x78, 0x1c, 0x0b, 0xce, 0x39, 0x23, 0xc5, 0xfb, 0x19, 0x61, 0xc7, 0x50, 0xcf, 0x29, 0x80,
	0xaf, 0x60, 0x59, 0xa5, 0x52, 0x8c, 0x96, 0xda, 0xd5, 0xce, 0x16, 0x5f, 0xdc, 0x85, 0x6f, 0x22,
	0xd9, 0x0e, 0x34, 0x3e, 0x90, 0x3c, 0x8b, 0x48, 0xe8, 0xd6, 0xef, 0x52, 0x2d, 0x6a, 0x92, 0x1d,
	0xc0, 0x46, 0xea, 0x40, 0x0c, 0xde, 0x4b, 0x28, 0x6b, 0x44, 0x6e, 0xab, 0xd7, 0xf9, 0x47, 0x19,
	0x08, 0x32, 0x10, 0x1f, 0x05, 0x42, 0x1d, 0xf1, 0xe3, 0x10, 0x76, 0x0c, 0x78, 0x40, 0x13, 0x4a,
	0xed, 0xa5, 0xa4, 0x64, 0x1c, 0x5b, 0x32, 0x8b, 0x34, 0xc8, 0x3a, 0xd0, 0x34, 0x99, 0xfe, 0xe1,
	0x0e, 0xa7, 0xb0, 0xd9, 0x9d, 0x73, 0xba, 0x77, 0x73, 0x72, 0xf0, 0x88, 0x0e, 0x2c, 0xb1, 0x17,
	0x6d, 0xb1, 0xb3, 0x5d, 0x68, 0x66, 0x32, 0x3e, 0x5a, 0x54, 0x9d, 0x9f, 0x4b, 0xb0, 0xd4, 0x9d,
	0xc9, 0x31, 0xbe, 0x85, 0x6a, 0x62, 0x3b, 0x61, 0x9d, 0x67, 0x97, 0xb7, 0xd7, 0xe0, 0x39, 0x0b,
	0x8c, 0x15, 0xf0, 0x0d, 0xc0, 0x7c, 0xca, 0x11, 0x79, 0x66, 0x0d, 0x79, 0x75, 0x9e, 0x5d, 0x03,
	0xac, 0xa0, 0x8a, 0x26, 0x86, 0x01, 0xeb, 0x3c, 0x3b, 0x77, 0x5e, 0x83, 0xe7, 0xcc, 0x0b, 0x2b,
	0xe0, 0x3b, 0xa8, 0x25, 0x35, 0x86, 0x8d, 0x3c, 0xc9, 0x79, 0x9b, 0xdc, 0x3c, 0x52, 0xfc, 0xf6,
	0x91, 0xe2, 0x87, 0xea, 0x91, 0x62, 0x05, 0x7c, 0x0f, 0x6b, 0x96, 0x9a, 0x70, 0x83, 0xe7, 0xc9,
	0xd1, 0xdb, 0xe4, 0xb9, 0xa2, 0x63, 0x05, 0xdc, 0x85, 0x6a, 0x42, 0x49, 0x58, 0xe7, 0x59, 0x5d,
	0xdd, 0x53, 0xff, 0x08, 0xd6, 0xd3, 0xea, 0x41, 0x97, 0x2f, 0x10, 0xd4, 0xbd, 0x79, 0x9e, 0xa4,
	0xf8, 0xc7, 0x26, 0xcf, 0xd7, 0x98, 0xe7, 0xf2, 0x05, 0x52, 0x61, 0x85, 0xbd, 0xea, 0xe7, 0x55,
	0xf5, 0xc2, 0x9f, 0xea, 0xfc, 0x65, 0x5d, 0xe6, 0xf5, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc9,
	0xa8, 0xc1, 0x5b, 0x01, 0x08, 0x00, 0x00,
}
