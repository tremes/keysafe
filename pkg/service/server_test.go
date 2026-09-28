package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"keysafe/pkg/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func TestKeyCreation(t *testing.T) {
	tests := []struct {
		name        string
		requestBody io.Reader
		testKeyID   string
	}{
		{
			name: "sucessful key creation",
		},
		{
			name:        "client cannot pass own key ID",
			requestBody: strings.NewReader(`{"key_id":"550e8400-e29b-41d4-a716-446655440000"}`),
			testKeyID:   "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testKeyStore := store.NewMemoryStore()
			testServer := New(testKeyStore)
			httpServer := httptest.NewServer(http.HandlerFunc(testServer.newKeyHandler))
			defer httpServer.Close()

			testUUID, err := createNewTestKey(t.Context(), httpServer.URL+"/keys", tt.requestBody)
			if err != nil {
				t.Fatalf("failed to create a new test key: %v", err)
			}

			if tt.testKeyID != "" && testUUID.String() == tt.testKeyID {
				t.Fatalf("provided key ID was used %s", tt.testKeyID)
			}
			_, err = testKeyStore.GetKey(t.Context(), testUUID.String())
			if err != nil {
				t.Fatalf("created key was not stored: %v", err)
			}
		})
	}
}

// createNewTestKey is a test helper function to create a new key for test purposes. Returns UUID
// of a newly create key or an error.
func createNewTestKey(ctx context.Context, url string, requestBody io.Reader) (*uuid.UUID, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v ", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the data: %v ", err)
	}
	var kRes keyIDResponse
	err = json.Unmarshal(data, &kRes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall the data: %v ", err)
	}

	err = uuid.Validate(kRes.UUID.String())
	if err != nil {
		return nil, fmt.Errorf("invalid UUID received: %v ", err)
	}
	return &kRes.UUID, nil
}

func TestEncryptionAndDecryption(t *testing.T) {
	tests := []struct {
		name               string
		customPayload      string
		testPlainText      string
		expectedStatusCode int
	}{
		{
			name:               "successful encryption path",
			testPlainText:      "SGVsbG8=", // hello base64 encoded
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "empty plaintext",
			testPlainText:      "",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "input data is unknown JSON",
			customPayload:      `{"id":"a","plaintext":"b"}`,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "input data is not JSON",
			customPayload:      `"id"="a","plaintext"="b"`,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "input data is not base64 encoded",
			testPlainText:      "hello",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "input data is with invalid key",
			customPayload:      `{"key_id":"not-uuid","plaintext":"SGVsbG8="}`,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "use non-existing key ID for encryption",
			testPlainText:      "SGVsbG8=", // hello base64 encoded
			customPayload:      `{"key_id":"11112222-aaaa-bbbb-a716-446655440000","plaintext":"SGVsbG8="}`,
			expectedStatusCode: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testKeyStore := store.NewMemoryStore()
			testServer := New(testKeyStore)
			testRouter := mux.NewRouter()
			testRouter.HandleFunc("/keys", testServer.newKeyHandler).Methods(http.MethodPost)
			testRouter.HandleFunc("/encrypt", testServer.encryptHandler).Methods(http.MethodPost)
			testRouter.HandleFunc("/decrypt", testServer.decryptHandler).Methods(http.MethodPost)

			httpServer := httptest.NewServer(testRouter)
			defer httpServer.Close()

			testUUID, err := createNewTestKey(t.Context(), httpServer.URL+"/keys", nil)
			if err != nil {
				t.Fatalf("failed to create a new test key: %v", err)
			}

			// override the payload if not empty
			var encryptionReqBody string
			if tt.customPayload != "" {
				encryptionReqBody = tt.customPayload
			} else {
				encryptionReqBody = fmt.Sprintf(`{"key_id":"%s","plaintext":"%s"}`, testUUID, tt.testPlainText)
			}

			// encryption request
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, httpServer.URL+"/encrypt", strings.NewReader(encryptionReqBody))
			if err != nil {
				t.Fatalf("failed to create encrypt request: %v", err)
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("encrypt POST request failed: %v", err)
			}
			defer res.Body.Close()
			if res.StatusCode != tt.expectedStatusCode {
				t.Fatalf("unexpected status code: %d", res.StatusCode)
			}
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("failed to read the data: %v", err)
			}
			if tt.expectedStatusCode != http.StatusOK {
				if string(data) != unableToEncryptData+"\n" {
					t.Fatalf("unexpected data received: %s", string(data))
				}
				return
			}
			var testRes cipherResponse
			err = json.Unmarshal(data, &testRes)
			if err != nil {
				t.Fatalf("failed to unmarshal the data: %v", err)
			}

			// decryption request
			decryptionReqBody := fmt.Sprintf(`{"key_id":"%s","ciphertext":"%s"}`, testUUID, testRes.CipherText)
			reqDec, err := http.NewRequestWithContext(t.Context(), http.MethodPost, httpServer.URL+"/decrypt", strings.NewReader(decryptionReqBody))
			if err != nil {
				t.Fatalf("failed to create decrypt request: %v", err)
			}
			resDec, err := http.DefaultClient.Do(reqDec)
			if err != nil {
				t.Fatalf("decrypt POST request failed: %v", err)
			}
			defer resDec.Body.Close()

			plainTextData, err := io.ReadAll(resDec.Body)
			if err != nil {
				t.Fatalf("failed to read the data: %v", err)
			}
			if tt.expectedStatusCode != http.StatusOK {
				t.Fatalf("unexpected data received: %s", string(plainTextData))
				return
			}
			var pTxRes plainTextResponse
			err = json.Unmarshal(plainTextData, &pTxRes)
			if err != nil {
				t.Fatalf("failed to unmarshal the data: %v", err)
			}
			if pTxRes.PlainText != tt.testPlainText {
				t.Fatalf("unexpected decyrpted text: %s", pTxRes.PlainText)
			}
		})
	}
}
