package signature

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderXSignature         = "X-Signature"
	HeaderXTimestamp         = "X-Timestamp"
	HeaderXNonce             = "X-Nonce"
	HeaderXForwardedProto    = "X-Forwarded-Proto"
	HeaderXForwardedProtocol = "X-Forwarded-Protocol"
	HeaderXForwardedSsl      = "X-Forwarded-Ssl"
	HeaderXUrlScheme         = "X-Url-Scheme"

	defaultMaxSignatureAge       = 15 * time.Second
	maxBodySize            int64 = 2 * 1024
)

type URLExtractor func(r *http.Request) (string, error)

type Validator struct {
	signer          *Signer
	MaxSignatureAge time.Duration
	URL             string
	URLExtractor    URLExtractor
}

func NewValidator(key string) *Validator {
	return &Validator{
		signer:          NewSigner(key),
		MaxSignatureAge: defaultMaxSignatureAge,
	}
}

func (v *Validator) ValidRequest(r *http.Request) error {
	signature := r.Header.Get(HeaderXSignature)
	timestamp := r.Header.Get(HeaderXTimestamp)
	nonce := r.Header.Get(HeaderXNonce)
	if signature == "" {
		return errors.New("signature header is missing")
	}
	if timestamp == "" {
		return errors.New("timestamp header is missing")
	}
	if nonce == "" {
		return errors.New("nonce header is missing")
	}

	created, err := parseTime(timestamp)
	if err != nil {
		return err
	}

	if err = validateTime(created, v.MaxSignatureAge); err != nil {
		return err
	}

	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		return err
	}

	if !v.signer.Verify(signature, nonce, created, r.Method, r.RequestURI, b) {
		return errors.New("invalid signature")
	}

	r.Body = io.NopCloser(bytes.NewBuffer(b))
	return nil
}

func (v *Validator) Validate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.ValidRequest(r); err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (v *Validator) createFullUrl(r *http.Request) (string, error) {
	if v.URL != "" {
		return fmt.Sprintf("%s%s", v.URL, r.RequestURI), nil
	}

	if v.URLExtractor != nil {
		return v.URLExtractor(r)
	}

	return DefaultURLExtractor(r)
}

func DefaultURLExtractor(r *http.Request) (string, error) {
	scheme := extractScheme(r)
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return "", errors.New("destination host of the request could not be determined")
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI()), nil
}

func parseTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(sec, 0), nil
}

func validateTime(created time.Time, maxAge time.Duration) error {
	now := time.Now()

	if now.Add(-maxAge).After(created) {
		return errors.New("signature expired")
	}

	return nil
}

func extractScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get(HeaderXForwardedProto); scheme != "" {
		return scheme
	}
	if scheme := r.Header.Get(HeaderXForwardedProtocol); scheme != "" {
		return scheme
	}
	if ssl := r.Header.Get(HeaderXForwardedSsl); ssl == "on" {
		return "https"
	}
	if scheme := r.Header.Get(HeaderXUrlScheme); scheme != "" {
		return scheme
	}
	return "http"
}
