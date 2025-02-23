package signature

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSigner_Sign(t *testing.T) {
	timestamp := time.Unix(1739394973, 0)
	method := http.MethodPost
	nonce := "2b14ad6812bb414f75e39a6354c7fe79"
	url := "https://gateway.seven.io/api/sms"
	content := []byte(`{"to":"49170123456789","text":"Hello World! :-)","from":"seven.io"}`)

	signer := NewSigner("YOUR_SIGN_KEY")
	signature := signer.Sign(nonce, timestamp, method, url, content)
	expectedSignature := "ca1cd94be33c6d22487b1e27e2179e0babf1133d26164e156fe19d1a0f7451aa"
	assert.Equal(t, signature, expectedSignature)

	isValid := signer.Verify(signature, nonce, timestamp, method, url, content)
	assert.True(t, isValid)
}
