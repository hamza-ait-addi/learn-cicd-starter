package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		expected   string
		expectedErr error
	}{
		{
			name:       "valid ApiKey header",
			headers:    http.Header{"Authorization": []string{"ApiKey my-api-key-123"}},
			expected:   "my-api-key-123",
			expectedErr: nil,
		},
		{
			name:       "missing authorization header",
			headers:    http.Header{},
			expected:   "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed header no space",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			expected:   "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:       "wrong auth scheme",
			headers:    http.Header{"Authorization": []string{"Bearer token-here"}},
			expected:   "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expected {
				t.Errorf("expected key %q, got %q", tt.expected, key)
			}

			if tt.expectedErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedErr)
				} else if err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error %q, got %q", tt.expectedErr.Error(), err.Error())
				}
			}
		})
	}
}
