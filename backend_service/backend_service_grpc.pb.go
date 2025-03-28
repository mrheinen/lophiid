// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: backend_service.proto

package backend_service

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	BackendService_HandleProbe_FullMethodName       = "/BackendService/HandleProbe"
	BackendService_SendStatus_FullMethodName        = "/BackendService/SendStatus"
	BackendService_SendSourceContext_FullMethodName = "/BackendService/SendSourceContext"
	BackendService_HandleUploadFile_FullMethodName  = "/BackendService/HandleUploadFile"
	BackendService_SendPingStatus_FullMethodName    = "/BackendService/SendPingStatus"
)

// BackendServiceClient is the client API for BackendService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BackendServiceClient interface {
	HandleProbe(ctx context.Context, in *HandleProbeRequest, opts ...grpc.CallOption) (*HandleProbeResponse, error)
	SendStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	SendSourceContext(ctx context.Context, in *SendSourceContextRequest, opts ...grpc.CallOption) (*SendSourceContextResponse, error)
	HandleUploadFile(ctx context.Context, in *UploadFileRequest, opts ...grpc.CallOption) (*UploadFileResponse, error)
	SendPingStatus(ctx context.Context, in *SendPingStatusRequest, opts ...grpc.CallOption) (*SendPingStatusResponse, error)
}

type backendServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewBackendServiceClient(cc grpc.ClientConnInterface) BackendServiceClient {
	return &backendServiceClient{cc}
}

func (c *backendServiceClient) HandleProbe(ctx context.Context, in *HandleProbeRequest, opts ...grpc.CallOption) (*HandleProbeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(HandleProbeResponse)
	err := c.cc.Invoke(ctx, BackendService_HandleProbe_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) SendStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StatusResponse)
	err := c.cc.Invoke(ctx, BackendService_SendStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) SendSourceContext(ctx context.Context, in *SendSourceContextRequest, opts ...grpc.CallOption) (*SendSourceContextResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SendSourceContextResponse)
	err := c.cc.Invoke(ctx, BackendService_SendSourceContext_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) HandleUploadFile(ctx context.Context, in *UploadFileRequest, opts ...grpc.CallOption) (*UploadFileResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UploadFileResponse)
	err := c.cc.Invoke(ctx, BackendService_HandleUploadFile_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) SendPingStatus(ctx context.Context, in *SendPingStatusRequest, opts ...grpc.CallOption) (*SendPingStatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SendPingStatusResponse)
	err := c.cc.Invoke(ctx, BackendService_SendPingStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BackendServiceServer is the server API for BackendService service.
// All implementations must embed UnimplementedBackendServiceServer
// for forward compatibility
type BackendServiceServer interface {
	HandleProbe(context.Context, *HandleProbeRequest) (*HandleProbeResponse, error)
	SendStatus(context.Context, *StatusRequest) (*StatusResponse, error)
	SendSourceContext(context.Context, *SendSourceContextRequest) (*SendSourceContextResponse, error)
	HandleUploadFile(context.Context, *UploadFileRequest) (*UploadFileResponse, error)
	SendPingStatus(context.Context, *SendPingStatusRequest) (*SendPingStatusResponse, error)
	mustEmbedUnimplementedBackendServiceServer()
}

// UnimplementedBackendServiceServer must be embedded to have forward compatible implementations.
type UnimplementedBackendServiceServer struct {
}

func (UnimplementedBackendServiceServer) HandleProbe(context.Context, *HandleProbeRequest) (*HandleProbeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HandleProbe not implemented")
}
func (UnimplementedBackendServiceServer) SendStatus(context.Context, *StatusRequest) (*StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendStatus not implemented")
}
func (UnimplementedBackendServiceServer) SendSourceContext(context.Context, *SendSourceContextRequest) (*SendSourceContextResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendSourceContext not implemented")
}
func (UnimplementedBackendServiceServer) HandleUploadFile(context.Context, *UploadFileRequest) (*UploadFileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HandleUploadFile not implemented")
}
func (UnimplementedBackendServiceServer) SendPingStatus(context.Context, *SendPingStatusRequest) (*SendPingStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendPingStatus not implemented")
}
func (UnimplementedBackendServiceServer) mustEmbedUnimplementedBackendServiceServer() {}

// UnsafeBackendServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BackendServiceServer will
// result in compilation errors.
type UnsafeBackendServiceServer interface {
	mustEmbedUnimplementedBackendServiceServer()
}

func RegisterBackendServiceServer(s grpc.ServiceRegistrar, srv BackendServiceServer) {
	s.RegisterService(&BackendService_ServiceDesc, srv)
}

func _BackendService_HandleProbe_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HandleProbeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).HandleProbe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_HandleProbe_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).HandleProbe(ctx, req.(*HandleProbeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_SendStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).SendStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_SendStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).SendStatus(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_SendSourceContext_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendSourceContextRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).SendSourceContext(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_SendSourceContext_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).SendSourceContext(ctx, req.(*SendSourceContextRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_HandleUploadFile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UploadFileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).HandleUploadFile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_HandleUploadFile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).HandleUploadFile(ctx, req.(*UploadFileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_SendPingStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendPingStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).SendPingStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_SendPingStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).SendPingStatus(ctx, req.(*SendPingStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// BackendService_ServiceDesc is the grpc.ServiceDesc for BackendService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var BackendService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "BackendService",
	HandlerType: (*BackendServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "HandleProbe",
			Handler:    _BackendService_HandleProbe_Handler,
		},
		{
			MethodName: "SendStatus",
			Handler:    _BackendService_SendStatus_Handler,
		},
		{
			MethodName: "SendSourceContext",
			Handler:    _BackendService_SendSourceContext_Handler,
		},
		{
			MethodName: "HandleUploadFile",
			Handler:    _BackendService_HandleUploadFile_Handler,
		},
		{
			MethodName: "SendPingStatus",
			Handler:    _BackendService_SendPingStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "backend_service.proto",
}
