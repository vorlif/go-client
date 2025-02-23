package signature

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Signer struct {
	Key string
}

func NewSigner(key string) *Signer {
	return &Signer{Key: key}
}

func (s *Signer) Sign(nonce string, timestamp time.Time, httpMethod, targetUrl string, content []byte) string {
	hash := md5.Sum(content)
	hexHash := hex.EncodeToString(hash[:])

	buff := bytes.NewBuffer(nil)
	_, _ = fmt.Fprintf(buff, "%d\n%s\n%s\n%s\n%s", timestamp.Unix(), nonce, httpMethod, targetUrl, hexHash)
	mac := hmac.New(sha256.New, []byte(s.Key))
	mac.Write(buff.Bytes())
	messageMAC := mac.Sum(nil)
	return hex.EncodeToString(messageMAC)
}

func (s *Signer) Verify(messageMAC string, nonce string, timestamp time.Time, httpMethod, targetUrl string, content []byte) bool {
	expectedMAC := s.Sign(nonce, timestamp, httpMethod, targetUrl, content)
	return hmac.Equal([]byte(messageMAC), []byte(expectedMAC))
}
