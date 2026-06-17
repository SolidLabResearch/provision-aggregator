package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aggregator-provision/internal/httpapi"
)

func main() {
	cfg := httpapi.DefaultConfig("http://localhost:8080")
	configPath := os.Getenv("AGGREGATOR_CONFIG")
	if configPath == "" {
		configPath = "aggregator.config.json"
	}
	var err error
	cfg, err = httpapi.LoadOptionalConfigFile(configPath, cfg)
	if err != nil {
		log.Fatalf("load config %s: %v", configPath, err)
	}
	aggregator := httpapi.NewServer(cfg)
	httpServer := &http.Server{
		Addr:    cfg.ListenAddr(),
		Handler: aggregator.Routes(),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	log.Printf("aggregator server listening on %s (public base URL %s)", cfg.LocalURL(), cfg.BaseURL)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-stop
	if err := aggregator.Shutdown(); err != nil {
		log.Printf("aggregator AS cleanup failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
