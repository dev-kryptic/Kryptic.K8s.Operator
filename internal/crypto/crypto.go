// Package crypto implements the client half of Kryptic's end-to-end
// encryption that the operator needs to open a secrets bundle: Argon2id key
// derivation (unwraps the machine private key from the client secret), the
// P-256 ECDH sealed box (unwraps the org key sealed to the machine), and the
// AES-256-GCM secret envelope (decrypts the values). Open-only - the operator
// never encrypts. Wire formats and parameters are locked by the interop
// vectors in the Kryptic.Encryption repository and match the C#, browser, and
// daemon implementations byte for byte.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2SaltSize matches Kryptic.Encryption's Argon2Parameters.
	Argon2SaltSize = 16
	// Argon2KeySize is the derived key length (AES-256).
	Argon2KeySize = 32

	publicKeySize = 65 // uncompressed SEC1 P-256 point: 0x04 || X || Y
	nonceSize     = 12
	tagSize       = 16
)

var sealedBoxLabel = []byte("kryptic-sealed-box-v1")

// Argon2idKey derives the machine-key unwrap key from the client secret using
// the parameter set version stored with the machine's key record. Version 1 is
// 64 MiB, 3 passes, 4 lanes, 32-byte output.
func Argon2idKey(version int, secret string, salt []byte) ([]byte, error) {
	if version != 1 {
		return nil, fmt.Errorf("unknown Argon2 parameter set version %d", version)
	}
	if len(salt) != Argon2SaltSize {
		return nil, fmt.Errorf("argon2 salt must be %d bytes", Argon2SaltSize)
	}
	return argon2.IDKey([]byte(secret), salt, 3, 64*1024, 4, Argon2KeySize), nil
}

// OpenSealedBox opens "sbx.v1.<keyId>.<ephemeralPub>.<nonce>.<ct+tag>" with
// the recipient key pair: ECDH against the ephemeral public key, HKDF-SHA256
// expanded to the AES key and nonce (bound to both public keys), AES-256-GCM.
func OpenSealedBox(recipientPublic, recipientPrivate []byte, serialized string) ([]byte, error) {
	parts := strings.Split(serialized, ".")
	if len(parts) != 6 || parts[0] != "sbx" || parts[1] != "v1" {
		return nil, errors.New("value is not a valid kryptic sealed box")
	}

	enc := base64.RawURLEncoding
	ephemeralPub, err := enc.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key encoding: %w", err)
	}
	nonce, err := enc.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid nonce encoding: %w", err)
	}
	ciphertext, err := enc.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	if len(ephemeralPub) != publicKeySize || ephemeralPub[0] != 0x04 {
		return nil, errors.New("ephemeral public key must be a 65-byte uncompressed SEC1 point")
	}
	if len(nonce) != nonceSize || len(ciphertext) < tagSize {
		return nil, errors.New("malformed sealed box")
	}

	private, err := ecdh.P256().NewPrivateKey(recipientPrivate)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient private key: %w", err)
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("ECDH agreement: %w", err)
	}

	info := make([]byte, 0, len(sealedBoxLabel)+len(ephemeralPub)+len(recipientPublic))
	info = append(info, sealedBoxLabel...)
	info = append(info, ephemeralPub...)
	info = append(info, recipientPublic...)
	okm := hkdfSHA256(shared, nil, info, 32+nonceSize)

	plaintext, err := aesGCMOpen(okm[:32], okm[32:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("sealed box authentication failed")
	}
	return plaintext, nil
}

// OpenEnvelope decrypts "v1.<keyId>.<nonce>.<ciphertext+tag>" with the given
// 256-bit key. The associated data must match what the encrypting client bound
// the ciphertext to.
func OpenEnvelope(key []byte, serialized string, associatedData []byte) ([]byte, error) {
	parts := strings.Split(serialized, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return nil, errors.New("value is not a valid kryptic secret envelope")
	}

	enc := base64.RawURLEncoding
	nonce, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid envelope nonce encoding: %w", err)
	}
	ciphertext, err := enc.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid envelope ciphertext encoding: %w", err)
	}
	if len(nonce) != nonceSize || len(ciphertext) < tagSize {
		return nil, errors.New("malformed secret envelope")
	}

	plaintext, err := aesGCMOpen(key, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, errors.New("envelope authentication failed - wrong key or tampered ciphertext")
	}
	return plaintext, nil
}

// SecretContext builds the associated data binding a secret value envelope to
// its definition + environment row, matching the browser and the C# engine.
func SecretContext(definitionID, environmentID string) []byte {
	return []byte("secret:" + strings.ToLower(definitionID) + ":env:" + strings.ToLower(environmentID))
}

func aesGCMOpen(key, nonce, ciphertextWithTag, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertextWithTag, associatedData)
}

// hkdfSHA256 is RFC 5869 extract-and-expand with SHA-256.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	var okm []byte
	var block []byte
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
