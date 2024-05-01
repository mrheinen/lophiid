package auth

import (
	"loophid/pkg/database"
	"strings"
	"testing"
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

			auth := NewAuthenticator(&fakeDbClient)

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
