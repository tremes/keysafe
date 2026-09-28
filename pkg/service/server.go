package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"keysafe/pkg/store"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Server is type implementing HTTP handlers
// to work with the underlying key store
type Server struct {
	keyStore   store.KeyStore
	httpServer *http.Server
}

// New is a constructor creating a new HttpServer
// with the provided keyStore
func New(ks store.KeyStore) *Server {
	return &Server{
		keyStore: ks,
		httpServer: &http.Server{
			Addr:              ":8080",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
		},
	}
}

type operation string
type status string

const (
	decrypt   operation = "decrypt"
	encrypt   operation = "encrypt"
	createKey operation = "create_key"
	listKeys  operation = "list_keys"

	success status = "success"
	failure status = "failure"

	unableToCreateKey   string = "unable to create key"
	unableToEncryptData string = "unable to encrypt the data"
	unableToDecryptData string = "unable to decrypt the data"
	unableToGetKeys     string = "unable to get the keys"

	contentType         = "Content-Type"
	appJSONMIME         = "application/json"
	maxRequestBodyBytes = 1048576
)

// Start starts new HTTP server
func (s *Server) Start() error {
	r := mux.NewRouter()
	r.HandleFunc("/keys", s.newKeyHandler).Methods(http.MethodPost)
	r.HandleFunc("/keys", s.getKeyHandler).Methods(http.MethodGet)
	r.HandleFunc("/encrypt", s.encryptHandler).Methods(http.MethodPost)
	r.HandleFunc("/decrypt", s.decryptHandler).Methods(http.MethodPost)

	s.httpServer.Handler = r

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server failed to shut down", "error", err)
		}

	}()
	slog.Info("Keysafe service is running and listening on port 8080")
	if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed to start: %v", err)
	}
	return nil
}

// newKeyHandler implements HTTP POST to create a new key.
func (s *Server) newKeyHandler(res http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	keyID, err := uuid.NewRandom()
	if err != nil {
		slog.Error("Failed to generate key ID", "error", err)
		http.Error(res, unableToCreateKey, http.StatusInternalServerError)
		auditLog(createKey, nil, failure)
		return
	}

	// Generate a 32-byte AES-256 key.
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		slog.Error("Failed to generate the key", "error", err)
		http.Error(res, unableToCreateKey, http.StatusInternalServerError)
		auditLog(createKey, &keyID, failure)
		return
	}

	// store the key pair
	err = s.keyStore.SaveKey(req.Context(), keyID.String(), key)
	if err != nil {
		slog.Error("Failed to store the new key data")
		http.Error(res, unableToCreateKey, http.StatusConflict)
		auditLog(createKey, &keyID, failure)
		return
	}

	kReq := keyIDResponse{
		UUID: keyID,
	}

	data, err := json.Marshal(kReq)
	if err != nil {
		slog.Error("Failed to marshal key response", "error", err)
		http.Error(res, unableToCreateKey, http.StatusInternalServerError)
		auditLog(createKey, &keyID, failure)
		return
	}

	res.Header().Set(contentType, appJSONMIME)
	res.WriteHeader(http.StatusCreated)
	if _, err := res.Write(data); err != nil {
		slog.Error("Failed to write key response", "error", err)
		auditLog(createKey, &keyID, failure)
		return
	}
	auditLog(createKey, &keyID, success)
}

// getKeyHandler implements HTTP GET to obtain all the keys from the Keystore
func (s *Server) getKeyHandler(res http.ResponseWriter, req *http.Request) {
	keys, err := s.keyStore.ListKeys(req.Context())
	if err != nil {
		slog.Error("Failed to list the keys from the store")
		res.WriteHeader(http.StatusInternalServerError)
		auditLog(listKeys, nil, failure)
		return
	}
	kList := keyIDsList{
		Keys: keys,
	}

	data, err := json.Marshal(kList)
	if err != nil {
		slog.Error("Failed to marshal the data", "error", err)
		http.Error(res, unableToGetKeys, http.StatusInternalServerError)
		auditLog(listKeys, nil, failure)
		return
	}

	res.Header().Set(contentType, appJSONMIME)
	_, err = res.Write(data)
	if err != nil {
		slog.Error("Failed to write the response", "error", err)
		auditLog(listKeys, nil, failure)
		return
	}
	auditLog(listKeys, nil, success)
}

// encryptHandler implements HTTP POST to encrypt incoming plaintext data
func (s *Server) encryptHandler(res http.ResponseWriter, req *http.Request) {
	// read and decode request
	dec := json.NewDecoder(http.MaxBytesReader(res, req.Body, maxRequestBodyBytes))
	defer req.Body.Close()
	dec.DisallowUnknownFields()

	var eReq encryptRequest
	err := dec.Decode(&eReq)
	if err != nil {
		slog.Error("Failed to decode incoming data")
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(res, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(res, unableToEncryptData, http.StatusBadRequest)
		}
		auditLog(encrypt, nil, failure)
		return
	}

	// obtain the corresponding key by UUID
	key, err := s.keyStore.GetKey(req.Context(), eReq.UUID.String())
	if err != nil {
		slog.Error("Failed to get key by UUID")
		http.Error(res, unableToEncryptData, http.StatusBadRequest)
		auditLog(encrypt, &eReq.UUID, failure)
		return
	}

	// base64 decode
	textDecoded, err := base64.StdEncoding.DecodeString(eReq.PlainText)
	if err != nil {
		slog.Error("Failed to base64 decode the data ", "error", err)
		http.Error(res, unableToEncryptData, http.StatusBadRequest)
		auditLog(encrypt, &eReq.UUID, failure)
		return
	}

	// encrypt with AES-256-GCM
	encryptedData, err := Encrypt(textDecoded, key)
	if err != nil {
		slog.Error("Failed to encrypt the data ", "error", err)
		http.Error(res, unableToEncryptData, http.StatusBadRequest)
		auditLog(encrypt, &eReq.UUID, failure)
		return
	}

	cipherRes := cipherResponse{
		CipherText: base64.StdEncoding.EncodeToString(encryptedData),
	}

	data, err := json.Marshal(cipherRes)
	if err != nil {
		slog.Error("Failed to marshal the encrypted data", "error", err)
		http.Error(res, unableToEncryptData, http.StatusInternalServerError)
		auditLog(encrypt, &eReq.UUID, failure)
		return
	}

	res.Header().Set(contentType, appJSONMIME)
	_, err = res.Write(data)
	if err != nil {
		slog.Error("Failed to write the response", "error", err)
		auditLog(encrypt, &eReq.UUID, failure)
		return
	}
	auditLog(encrypt, &eReq.UUID, success)
}

// decryptHandler implements HTTP POST to decrypt incoming cipher text
func (s *Server) decryptHandler(res http.ResponseWriter, req *http.Request) {
	// read and decode request
	dec := json.NewDecoder(http.MaxBytesReader(res, req.Body, maxRequestBodyBytes))
	defer req.Body.Close()
	dec.DisallowUnknownFields()

	var dReq decryptRequest
	err := dec.Decode(&dReq)
	if err != nil {
		slog.Error("Failed to decode incoming data")
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(res, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(res, unableToDecryptData, http.StatusBadRequest)
		}
		auditLog(decrypt, nil, failure)
		return
	}

	// obtain the corresponding key by UUID
	key, err := s.keyStore.GetKey(req.Context(), dReq.UUID.String())
	if err != nil {
		slog.Error("Failed to get key by UUID")
		http.Error(res, unableToDecryptData, http.StatusBadRequest)
		auditLog(decrypt, &dReq.UUID, failure)
		return
	}

	// base64 decode
	cipherTextDecoded, err := base64.StdEncoding.DecodeString(dReq.CipherText)
	if err != nil {
		slog.Error("Failed to base64 decode the data ", "error", err)
		http.Error(res, unableToDecryptData, http.StatusBadRequest)
		auditLog(decrypt, &dReq.UUID, failure)
		return
	}

	// decrypt with AES-256-GCM
	decryptedData, err := Decrypt(cipherTextDecoded, key)
	if err != nil {
		slog.Error("Failed to decrypt the data ", "error", err)
		http.Error(res, unableToDecryptData, http.StatusBadRequest)
		auditLog(decrypt, &dReq.UUID, failure)
		return
	}

	plainTextRes := plainTextResponse{
		PlainText: base64.StdEncoding.EncodeToString(decryptedData),
	}

	data, err := json.Marshal(plainTextRes)
	if err != nil {
		slog.Error("Failed to marshal the decrypted data", "error", err)
		http.Error(res, unableToDecryptData, http.StatusInternalServerError)
		auditLog(decrypt, &dReq.UUID, failure)
		return
	}

	res.Header().Set(contentType, appJSONMIME)
	_, err = res.Write(data)
	if err != nil {
		slog.Error("Failed to write the response", "error", err)
		auditLog(decrypt, &dReq.UUID, failure)
		return
	}
	auditLog(decrypt, &dReq.UUID, success)
}

func (h *Server) Stop(ctx context.Context) {
	h.httpServer.Shutdown(ctx)
}

// auditLog is a helper function for audit logging with slog
func auditLog(o operation, u *uuid.UUID, s status) {
	slog.Info("audit", "operation", o, "key_id", u, "status", s)
}
