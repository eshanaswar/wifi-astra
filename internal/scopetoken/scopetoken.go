// internal/scopetoken/scopetoken.go
package scopetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const tokenTTL = 5 * time.Minute

// Generate produces an HMAC-SHA256 token encoding:
//
//	moduleID|bssid|expiry
//
// where expiry is a Unix timestamp (seconds) and secret is the 32-byte
// per-session random key stored in SQLite.
func Generate(secret []byte, moduleID, bssid string) string {
	if len(secret) == 0 {
		return ""
	}
	expiry := time.Now().Add(tokenTTL).Unix()
	payload := fmt.Sprintf("%s|%s|%d", moduleID, bssid, expiry)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "|" + sig
}

// Verify returns nil if token is valid for the given moduleID and bssid.
// Returns a non-nil error if the signature is wrong, the token is expired,
// or the fields don't match.
func Verify(secret []byte, token, moduleID, bssid string) error {
	if len(secret) == 0 {
		return fmt.Errorf("scopetoken: secret must not be empty")
	}
	parts := strings.Split(token, "|")
	if len(parts) != 4 {
		return fmt.Errorf("malformed scope token")
	}
	gotModuleID, gotBSSID, expiryStr, gotSig := parts[0], parts[1], parts[2], parts[3]

	if gotModuleID != moduleID {
		return fmt.Errorf("token module mismatch: expected %s got %s", moduleID, gotModuleID)
	}
	if !strings.EqualFold(gotBSSID, bssid) {
		return fmt.Errorf("token BSSID mismatch")
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return fmt.Errorf("malformed expiry in scope token")
	}
	if time.Now().Unix() > expiry {
		return fmt.Errorf("scope token expired")
	}

	payload := fmt.Sprintf("%s|%s|%d", gotModuleID, gotBSSID, expiry)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotSig), []byte(expected)) {
		return fmt.Errorf("scope token signature invalid")
	}
	return nil
}
