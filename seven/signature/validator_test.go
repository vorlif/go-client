package signature

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultURLExtractor(t *testing.T) {
	cases := []struct {
		name        string
		expectedURL string
	}{
		{"scheme=http", "http://example.com/foo/bar"},
		{"scheme=https", "https://example.com/foo/bar"},
		{"port=443", "https://example.com:443/foo/bar"},
		{"with-query", "https://example.com:443/foo/bar?p1=A&p2"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, testCase.expectedURL, nil)
			url, err := DefaultURLExtractor(r)
			if assert.NoError(t, err) {
				assert.Equal(t, testCase.expectedURL, url)
			}
		})
	}
}
