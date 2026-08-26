package krypticapi

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/dev-kryptic/Kryptic.Encryption.Go/envelope"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/kdf"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/sealedbox"
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

	salt, err := kdf.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	unwrapKey, err := kdf.ForVersion(1, clientSecret, salt)
	if err != nil {
		t.Fatal(err)
	}
	wrappedPrivateKey, err := envelope.Seal(unwrapKey, "machinesecret_v1", machine.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}

	orgKey := make([]byte, 32)
	if _, err := rand.Read(orgKey); err != nil {
		t.Fatal(err)
	}
	grant, err := sealedbox.Seal(machinePublic, "org-key-1", orgKey)
	if err != nil {
		t.Fatal(err)
	}

	definitionId, environmentId := "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	secretEnvelope, err := envelope.Seal(
		orgKey, "org-key-1", []byte("postgres://localhost/app"),
		envelope.SecretContext(definitionId, environmentId),
	)
	if err != nil {
		t.Fatal(err)
	}

	keys := machineKeys{
		PublicKey:            enc.EncodeToString(machinePublic),
		WrappedPrivateKey:    wrappedPrivateKey,
		KdfSalt:              enc.EncodeToString(salt),
		KdfParametersVersion: 1,
	}
	bundle := cipherBundle{
		OrgKeyId:      "org-key-1",
		WrappedOrgKey: grant.Serialize(),
		Secrets: []bundleEntry{{
			Key:           "DATABASE_URL",
			Envelope:      secretEnvelope,
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
	salt, err := kdf.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	unwrapKey, err := kdf.ForVersion(1, "right-secret", salt)
	if err != nil {
		t.Fatal(err)
	}
	wrappedPrivateKey, err := envelope.Seal(unwrapKey, "machinesecret_v1", machine.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}

	keys := machineKeys{
		PublicKey:            enc.EncodeToString(machine.PublicKey().Bytes()),
		WrappedPrivateKey:    wrappedPrivateKey,
		KdfSalt:              enc.EncodeToString(salt),
		KdfParametersVersion: 1,
	}

	client := NewClient()
	_, err = client.decrypt(Credentials{ClientID: "kmi_x", ClientSecret: "wrong-secret"}, keys, cipherBundle{})
	if err == nil {
		t.Fatal("expected an error for the wrong client secret")
	}
}
