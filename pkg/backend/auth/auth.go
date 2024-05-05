package auth

import (
	"context"
	"fmt"
	"log/slog"
	"loophid/pkg/database"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Authenticator exposes a function for authenticating requests.
type Authenticator struct {
	dbClient database.DatabaseClient
}

// HoneypotMetadata contains metadata about a honeypot
type HoneypotMetadata struct {
	ID int64
	IP string
}

type honeypotMDKey struct{}

// ExactAuthTokenLength is the expected length of an authentication token.
var ExactAuthTokenLength = 64
var TokenHeaderName = "authorization"
var TokenHeaderPrefix = "Bearer "

func NewAuthenticator(dbClient database.DatabaseClient) *Authenticator {
	return &Authenticator{dbClient: dbClient}
}

// Authenticate checks that a token exists and is valid. It stores the
// metadata in the returned context and removes the token from the context.
func (a Authenticator) Authenticate(ctx context.Context) (newCtx context.Context, err error) {
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
	newCtx = context.WithValue(newCtx, honeypotMDKey{}, honeypotMD)
	return
}

func (a Authenticator) hasValidAuthToken(authValue string) (HoneypotMetadata, error) {
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

	hps, err := a.dbClient.SearchHoneypots(0, 1, fmt.Sprintf("auth_token:\"%s\"", authToken))
	if err != nil {
		return honeypotMD, status.Error(codes.Unauthenticated, "auth system unavailable")
	}

	if len(hps) != 1 {
		slog.Warn("could not find host for auth token")
		return honeypotMD, status.Error(codes.Unauthenticated, "invalid token")
	}

	honeypotMD.ID = hps[0].ID
	honeypotMD.IP = hps[0].IP

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
	honeypotMD := ctx.Value(honeypotMDKey{})

	switch md := honeypotMD.(type) {
	case HoneypotMetadata:
		return &md, true
	default:
		return nil, false
	}
}
