package scopetoken_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"wifi-astra/internal/scopetoken"
)

// generate a test secret
func testSecret() []byte {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return secret
}

func TestGenerateAndVerify_Valid(t *testing.T) {
	secret := testSecret()
	tok := scopetoken.Generate(secret, "D1", "AA:BB:CC:DD:EE:FF")
	if tok == "" {
		t.Fatal("Generate returned empty token")
	}
	if err := scopetoken.Verify(secret, tok, "D1", "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("Verify failed on valid token: %v", err)
	}
}

func TestVerify_CaseInsensitiveBSSID(t *testing.T) {
	secret := testSecret()
	tok := scopetoken.Generate(secret, "D1", "AA:BB:CC:DD:EE:FF")
	if err := scopetoken.Verify(secret, tok, "D1", "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Errorf("Verify should accept lowercase BSSID: %v", err)
	}
}

func TestVerify_WrongModule(t *testing.T) {
	secret := testSecret()
	tok := scopetoken.Generate(secret, "D1", "AA:BB:CC:DD:EE:FF")
	if err := scopetoken.Verify(secret, tok, "D2", "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("Verify should reject wrong module ID")
	}
}

func TestVerify_WrongBSSID(t *testing.T) {
	secret := testSecret()
	tok := scopetoken.Generate(secret, "D1", "AA:BB:CC:DD:EE:FF")
	if err := scopetoken.Verify(secret, tok, "D1", "11:22:33:44:55:66"); err == nil {
		t.Error("Verify should reject wrong BSSID")
	}
}

func TestVerify_TamperedHMAC(t *testing.T) {
	secret := testSecret()
	tok := scopetoken.Generate(secret, "D1", "AA:BB:CC:DD:EE:FF")
	// Corrupt last char of the token
	tampered := tok[:len(tok)-1] + "X"
	if err := scopetoken.Verify(secret, tampered, "D1", "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("Verify should reject tampered HMAC")
	}
}

func TestVerify_Malformed(t *testing.T) {
	secret := testSecret()
	if err := scopetoken.Verify(secret, "not|a|valid", "D1", "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("Verify should reject malformed token (wrong number of fields)")
	}
}

func TestVerify_NilSecret(t *testing.T) {
	tok := scopetoken.Generate(testSecret(), "D1", "AA:BB:CC:DD:EE:FF")
	if err := scopetoken.Verify(nil, tok, "D1", "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("Verify should reject nil secret")
	}
}

func TestGenerate_NilSecret(t *testing.T) {
	tok := scopetoken.Generate(nil, "D1", "AA:BB:CC:DD:EE:FF")
	if tok != "" {
		t.Error("Generate with nil secret should return empty string")
	}
}

func TestVerify_Expired(t *testing.T) {
	secret := testSecret()
	// Build a token whose expiry is 1 second in the past with a *valid* HMAC.
	// This directly exercises the expiry-check branch rather than the HMAC-check
	// branch (which is already covered by TestVerify_TamperedHMAC).
	expiry := time.Now().Add(-1 * time.Second).Unix()
	payload := fmt.Sprintf("D1|AA:BB:CC:DD:EE:FF|%d", expiry)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	tok := payload + "|" + sig

	if err := scopetoken.Verify(secret, tok, "D1", "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("Verify should reject an expired token")
	}
}
