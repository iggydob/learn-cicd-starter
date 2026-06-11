package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedErr   error
		errContains   string // Used to check dynamic text errors safely
	}{
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-token-12345"},
			},
			expectedKey: "secret-token-12345",
			expectedErr: nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization String",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Wrong Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer secret-token-12345"},
			},
			expectedKey: "",
			errContains: "malformed authorization header",
		},
		{
			name: "Malformed Header - Missing Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			errContains: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// 1. Assert on the error type/value
			if tt.expectedErr != nil {
				if !errors.Is(gotErr, tt.expectedErr) {
					t.Fatalf("expected error sentinel %v, got %v", tt.expectedErr, gotErr)
				}
			} else if tt.errContains != "" {
				if gotErr == nil {
					t.Fatalf("expected error containing %q, but got nil", tt.errContains)
				}
				if gotErr.Error() != tt.errContains {
					t.Fatalf("expected error string %q, got %q", tt.errContains, gotErr.Error())
				}
			} else if gotErr != nil {
				t.Fatalf("expected no error, but got %v", gotErr)
			}

			// 2. Assert on the returned API key
			if gotKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, gotKey)
			}
		})
	}
}
