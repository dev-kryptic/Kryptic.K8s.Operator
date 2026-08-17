package krypticapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/dev-kryptic/k8s-operator/internal/crypto"
)

// The operator only opens ciphertexts, so the test plays the browser: it wraps
// the machine private key under Argon2id(clientSecret), seals the org key to
// the machine public key, and encrypts values under the org key - then checks
// Client.decrypt recovers the plaintext through the whole chain.
func TestDecryptRunsTheFullChain(t *testing.T) {
	enc := base64.RawURLEncoding
	clientSecret := "kms_test_secret_value"

	machine, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machinePublic := machine.PublicKey().Bytes()

	salt := make([]byte, crypto.Argon2SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	unwrapKey := argon2.IDKey([]byte(clientSecret), salt, 3, 64*1024, 4, crypto.Argon2KeySize)

	orgKey := make([]byte, 32)
	if _, err := rand.Read(orgKey); err != nil {
		t.Fatal(err)
	}

	keys := machineKeys{
		PublicKey:            enc.EncodeToString(machinePublic),
		WrappedPrivateKey:    sealEnvelope(t, unwrapKey, "machine-secret-wrap-v1", machine.Bytes(), nil),
		KdfSalt:              enc.EncodeToString(salt),
		KdfParametersVersion: 1,
	}

	definitionId, environmentId := "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	bundle := cipherBundle{
		OrgKeyId:      "org-key-1",
		WrappedOrgKey: sealBox(t, machinePublic, "org-key-1", orgKey),
		Secrets: []bundleEntry{{
			Key:           "DATABASE_URL",
			Envelope:      sealEnvelope(t, orgKey, "org-key-1", []byte("postgres://localhost/app"), crypto.SecretContext(definitionId, environmentId)),
			DefinitionId:  definitionId,
			EnvironmentId: environmentId,
		}},
	}

	client := NewClient()
	pairs, err := client.decrypt(Credentials{ClientID: "kmi_x", ClientSecret: clientSecret}, keys, bundle)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pairs["DATABASE_URL"] != "postgres://localhost/app" {
		t.Fatalf("wrong plaintext: %q", pairs["DATABASE_URL"])
	}
}

func TestDecryptRejectsWrongClientSecret(t *testing.T) {
	enc := base64.RawURLEncoding

	machine, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, crypto.Argon2SaltSize)
	unwrapKey := argon2.IDKey([]byte("right-secret"), salt, 3, 64*1024, 4, crypto.Argon2KeySize)

	keys := machineKeys{
		PublicKey:            enc.EncodeToString(machine.PublicKey().Bytes()),
		WrappedPrivateKey:    sealEnvelope(t, unwrapKey, "machine-secret-wrap-v1", machine.Bytes(), nil),
		KdfSalt:              enc.EncodeToString(salt),
		KdfParametersVersion: 1,
	}

	client := NewClient()
	_, err = client.decrypt(Credentials{ClientID: "kmi_x", ClientSecret: "wrong-secret"}, keys, cipherBundle{})
	if err == nil {
		t.Fatal("expected an error for the wrong client secret")
	}
}

// sealEnvelope produces "v1.<keyId>.<nonce>.<ciphertext+tag>".
func sealEnvelope(t *testing.T, key []byte, keyID string, plaintext, associatedData []byte) string {
	t.Helper()
	enc := base64.RawURLEncoding

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, associatedData)
	return "v1." + keyID + "." + enc.EncodeToString(nonce) + "." + enc.EncodeToString(ciphertext)
}

// sealBox produces "sbx.v1.<keyId>.<ephemeralPub>.<nonce>.<ciphertext+tag>"
// with the derivation the crypto package expects.
func sealBox(t *testing.T, recipientPublic []byte, keyID string, plaintext []byte) string {
	t.Helper()
	enc := base64.RawURLEncoding

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.P256().NewPublicKey(recipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}

	ephemeralPub := ephemeral.PublicKey().Bytes()
	info := append(append([]byte("kryptic-sealed-box-v1"), ephemeralPub...), recipientPublic...)
	okm := hkdfExpand(shared, info, 44)
	key, nonce := okm[:32], okm[32:]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return "sbx.v1." + keyID + "." + enc.EncodeToString(ephemeralPub) + "." +
		enc.EncodeToString(nonce) + "." + enc.EncodeToString(ciphertext)
}

func hkdfExpand(ikm, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(ikm)
	prk := extract.Sum(nil)

	var okm, block []byte
	for counter := byte(1); len(okm) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		expand.Write(block)
		expand.Write(info)
		expand.Write([]byte{counter})
		block = expand.Sum(nil)
		okm = append(okm, block...)
	}
	return okm[:length]
}
