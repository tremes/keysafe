
KeySafe is an MVP for storing cryptographic keys. Storage is in-memory. The two main packages are:

* `pkg/service` - includes HTTP server exposing endpoints to communicate with the store over HTTP and cryptographic functions
* `pkg/store` - implementation of the in-memory storage.

The service uses a `KeyStore` interface so another storage backend can be implemetnted later. Encryption uses AES-256-GCM.

# How to run

Run the service locally:
```bash
make run
```

Build it with `make build`.

## Create a new key
```bash
curl -i -X POST -H "Content-Type: application/json" http://localhost:8080/keys
```

Use the returned `key_id` in the following requests.

## List keys

```bash
curl -i http://localhost:8080/keys
```

## Encrypt with the key

```bash
curl -i -X POST -H "Content-Type: application/json" -d '{"key_id":"<key-id>","plaintext":"SGVsbG8gd29ybGQhCg=="}' http://localhost:8080/encrypt
```

## Decrypt with the key

```bash
curl -i -X POST -H "Content-Type: application/json" -d '{"key_id":"<key-id>","ciphertext":"<ciphertext-from-encrypt>"}' http://localhost:8080/decrypt
```

# How to run unit tests:

Run the unit tests:

```bash
make test
```

# Limitations

Keys are lost when the service is restarted. 

# Improvements
* use HTTPS
* add authentication & authorization
* increase the test code coverage 
* error handling might likely be improved
* containerization - add Containerfile, Kubernetes manifests
* consider rate-limiting for the API
* provide OpenAPI (or similar) specification