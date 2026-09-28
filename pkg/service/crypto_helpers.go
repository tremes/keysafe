package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts the plain text data with the provided key with AES-256-GCM.
func Encrypt(plainText []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes")
	}

	// Create a new AES cipher block using the 32-byte key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Wrap the block with GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a unique nonce of standard GCM length
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext.
	// Pass 'nonce' as the first argument to Seal so the nonce is prepended
	// to the encrypted ciphertext output for easy storage/transmission.
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	return cipherText, nil
}

// Decrypt decrypts ciphertext encrypted with AES-256-GCM.
func Decrypt(cipherText []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and actual ciphertext content
	nonce, cipherTextData := cipherText[:nonceSize], cipherText[nonceSize:]

	// Decrypt and verify authentication tag
	plainText, err := gcm.Open(nil, nonce, cipherTextData, nil)
	if err != nil {
		return nil, err // Tag verification failed or decryption failed
	}

	return plainText, nil
}
