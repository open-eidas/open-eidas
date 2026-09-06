package enroll

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestComputeSignatureMatchesReferenceHMAC(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := buildCSR(key, Subject{CommonName: "Test TSU"})
	if err != nil {
		t.Fatal(err)
	}

	secret := "un-secret-partage"
	got := computeSignature(der, secret)

	// Reproduit indépendamment hmac_sha256_hex(pkcs10.data, secret) tel que
	// calculé côté OpenXPKI (CalculateRequestHMAC.pm) : HMAC-SHA256 sur les
	// octets DER bruts de la CSR, encodé en hexadécimal.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(der)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("signature = %q, attendu %q", got, want)
	}
	if len(got) != 64 {
		t.Errorf("longueur de signature inattendue: %d (attendu 64 caractères hex)", len(got))
	}
}

func TestComputeSignatureDiffersWithSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := buildCSR(key, Subject{CommonName: "Test TSU"})
	if err != nil {
		t.Fatal(err)
	}

	a := computeSignature(der, "secret-a")
	b := computeSignature(der, "secret-b")
	if a == b {
		t.Fatal("deux secrets différents ne doivent pas produire la même signature")
	}
}
