package auth

import (
	"context"
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"regexp"
	"strings"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Authenticator exposes a function for authenticating requests.
type Authenticator struct {
	dbClient  database.DatabaseClient
	authCache *util.StringMapCache[database.Honeypot]
}

// HoneypotMetadata contains metadata about a honeypot
type HoneypotMetadata struct {
	ID int64
	IP string
}

// HoneypotMDKey is the key for storing honeypot specific metadata in context.
type HoneypotMDKey struct{}

// ExactAuthTokenLength is the expected length of an authentication token.
var ExactAuthTokenLength = 64
var TokenHeaderName = "authorization"
var TokenHeaderPrefix = "Bearer "

func NewAuthenticator(dbClient database.DatabaseClient, authCache *util.StringMapCache[database.Honeypot]) *Authenticator {
	return &Authenticator{dbClient: dbClient, authCache: authCache}
}

// UnaryServerInterceptor returns a new unary server interceptors that performs per-request auth.
// This is a copy from the go grpcs middleware code. With the exception that it
// takes an array of methods that require no authentication check.
func CustomUnaryServerInterceptor(authFunc grpc_auth.AuthFunc, allowlistedMethods []string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var newCtx context.Context
		var err error

		for _, m := range allowlistedMethods {
			if info.FullMethod == m {
				return handler(ctx, req)
			}
		}

		if overrideSrv, ok := info.Server.(grpc_auth.ServiceAuthFuncOverride); ok {
			newCtx, err = overrideSrv.AuthFuncOverride(ctx, info.FullMethod)
		} else {
			newCtx, err = authFunc(ctx)
		}
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a new unary server interceptors that performs per-request auth.
// This is a copy from the go grpcs middleware code. With the exception that it
// takes an array of methods that require no authentication check.
func CustomStreamServerInterceptor(authFunc grpc_auth.AuthFunc, allowlistedMethods []string) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		var newCtx context.Context
		var err error

		for _, m := range allowlistedMethods {
			if info.FullMethod == m {
				wrapped := grpc_middleware.WrapServerStream(stream)
				wrapped.WrappedContext = newCtx
				return handler(srv, wrapped)
			}
		}

		if overrideSrv, ok := srv.(grpc_auth.ServiceAuthFuncOverride); ok {
			newCtx, err = overrideSrv.AuthFuncOverride(stream.Context(), info.FullMethod)
		} else {
			newCtx, err = authFunc(stream.Context())
		}
		if err != nil {
			return err
		}
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		return handler(srv, wrapped)
	}
}

// Authenticate checks that a token exists and is valid. It stores the
// metadata in the returned context and removes the token from the context.
// Auth tokens are fetched from the database and cached to reduce the amount of
// database calls. The cache timeout is set during the authCache initialization.
func (a *Authenticator) Authenticate(ctx context.Context) (newCtx context.Context, err error) {
	authValue, err := extractHeader(ctx, TokenHeaderName)
	if err != nil {
		return
	}

	honeypotMD, err := a.hasValidAuthToken(authValue)
	if err != nil {
		return
	}

	// Remove token from headers from here on
	newCtx = purgeHeader(ctx, TokenHeaderName)
	// Store the metadata
	newCtx = context.WithValue(newCtx, HoneypotMDKey{}, honeypotMD)
	return
}

func (a *Authenticator) hasValidAuthToken(authValue string) (HoneypotMetadata, error) {
	honeypotMD := HoneypotMetadata{}

	if !strings.HasPrefix(authValue, TokenHeaderPrefix) {
		slog.Warn("token misses bearer prefix")
		return honeypotMD, status.Error(codes.Unauthenticated, "invalid token format")
	}

	authToken := strings.TrimPrefix(authValue, TokenHeaderPrefix)
	if !regexp.MustCompile("^[a-zA-Z0-9]{64}$").MatchString(authToken) {
		slog.Warn("got invalid auth token", slog.String("token", authToken))
		return honeypotMD, status.Error(codes.Unauthenticated, "token does not validate")
	}

	var hp *database.Honeypot
	var err error

	hp, err = a.authCache.Get(authToken)
	if err != nil {
		hps, err := a.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("auth_token:\"%s\"", authToken))
		if err != nil {
			return honeypotMD, status.Error(codes.Unavailable, "auth system unavailable")
		}

		if len(hps) != 1 {
			slog.Warn("could not find host for auth token")
			return honeypotMD, status.Error(codes.Unauthenticated, "invalid token")
		}

		hp = &hps[0]
		a.authCache.Store(authToken, *hp)
	}

	honeypotMD.ID = hp.ID
	honeypotMD.IP = hp.IP

	return honeypotMD, nil
}

func extractHeader(ctx context.Context, header string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no headers in request")
	}

	authHeaders, ok := md[header]
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no header in request")
	}

	if len(authHeaders) != 1 {
		return "", status.Error(codes.Unauthenticated, "more than 1 header in request")
	}

	return authHeaders[0], nil
}

func purgeHeader(ctx context.Context, header string) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	mdCopy := md.Copy()
	mdCopy[header] = nil
	return metadata.NewIncomingContext(ctx, mdCopy)
}

// GetUserMetadata can be used to extract metadata stored in a context.
func GetHoneypotMetadata(ctx context.Context) (*HoneypotMetadata, bool) {
	honeypotMD := ctx.Value(HoneypotMDKey{})

	if honeypotMD == nil {
		return nil, false
	}

	switch md := honeypotMD.(type) {
	case HoneypotMetadata:
		return &md, true
	default:
		return nil, false
	}
}
