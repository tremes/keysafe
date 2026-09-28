package service

import "github.com/google/uuid"

// keyIDResponse is a helper type when creating a new key
type keyIDResponse struct {
	UUID uuid.UUID `json:"key_id"`
}

// keyIDsList is a helper type when listing keys
type keyIDsList struct {
	Keys []string `json:"keys"`
}

// encryptRequest is a helper type when encrypting data
type encryptRequest struct {
	UUID      uuid.UUID `json:"key_id"`
	PlainText string    `json:"plaintext"`
}

// cipherResponse is a helper type when
// responding with encrypted data
type cipherResponse struct {
	CipherText string `json:"ciphertext"`
}

// decryptRequest is a helper type when decrypting data
type decryptRequest struct {
	UUID       uuid.UUID `json:"key_id"`
	CipherText string    `json:"ciphertext"`
}

// plainText reponse is a helper type when
// responding with decrypted data
type plainTextResponse struct {
	PlainText string `json:"plaintext"`
}
