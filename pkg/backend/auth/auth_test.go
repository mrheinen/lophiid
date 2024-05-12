package auth

import (
	"context"
	"errors"
	"loophid/pkg/database"
	"loophid/pkg/util"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

func TestHasValidAuthToken(t *testing.T) {

	for _, test := range []struct {
		description   string
		authValue     string
		expectError   bool
		errorContains string
		metadata      HoneypotMetadata
	}{
		{
			description:   "missed prefix",
			authValue:     "dssdads ",
			expectError:   true,
			errorContains: "format",
			metadata:      HoneypotMetadata{},
		},
		{
			description:   "invalid token",
			authValue:     "Bearer aaa",
			expectError:   true,
			errorContains: "token does not validate",
			metadata:      HoneypotMetadata{},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fakeDbClient := database.FakeDatabaseClient{}
			authCache := util.NewStringMapCache[database.Honeypot]("test", time.Minute)
			auth := NewAuthenticator(&fakeDbClient, authCache)

			md, err := auth.hasValidAuthToken(test.authValue)
			if test.expectError {
				if err == nil {
					t.Fatal("expected error, got none")
				}

				if !strings.Contains(err.Error(), test.errorContains) {
					t.Fatalf("expected error to contain %s, got %s", test.errorContains, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if md != test.metadata {
				t.Errorf("expected metadata: %v, got %v", test.metadata, md)
			}
		})

	}
}

func TestAuthenticateWorksOk(t *testing.T) {

	testHoneypotID := 42
	fakeDbClient := database.FakeDatabaseClient{
		HoneypotToReturn: database.Honeypot{
			ID: int64(testHoneypotID),
			IP: "127.0.0.1",
		},
		ErrorToReturn: nil,
	}
	authCache := util.NewStringMapCache[database.Honeypot]("test", time.Minute)
	auth := NewAuthenticator(&fakeDbClient, authCache)

	testContext := context.Background()
	md := metadata.New(map[string]string{"authorization": "Bearer 03aa3f5e2779b625a455651b54866447f995a2970d164581b4073044435359ed"})
	testContext = metadata.NewIncomingContext(testContext, md)

	authCtx, err := auth.Authenticate(testContext)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}

	honeypotMetadata, ok := GetHoneypotMetadata(authCtx)
	if !ok {
		t.Errorf("expected metadata, got none")
		return
	}
	if honeypotMetadata.ID != int64(testHoneypotID) {
		t.Errorf("expected %d, got %d", testHoneypotID, honeypotMetadata.ID)
	}

	// We did a successful auth and during the auth there was a
	// database lookup and this was cached. A next auth attempt will
	// use the cache and we can test this by making sure the database
	// returns an error. If there was no cached result than the database
	// error would fail the auth attempt.
	fakeDbClient.ErrorToReturn = errors.New("AAAA")

	authCtx, err = auth.Authenticate(testContext)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}

	honeypotMetadata, ok = GetHoneypotMetadata(authCtx)
	if !ok {
		t.Errorf("expected metadata, got none")
		return
	}
	if honeypotMetadata.ID != int64(testHoneypotID) {
		t.Errorf("expected %d, got %d", testHoneypotID, honeypotMetadata.ID)
	}

}
