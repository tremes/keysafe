package main

import (
	"keysafe/pkg/service"
	"keysafe/pkg/store"
	"log/slog"
	"os"
)

func main() {
	handler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(handler))

	ms := store.NewMemoryStore()
	server := service.New(ms)
	err := server.Start()

	if err != nil {
		slog.Error("Keysafe failed to start", "error", err)
		os.Exit(1)
	}
}
