package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aggregator-provision/internal/httpapi"
)

func main() {
	var loggingLevelValue string
	flag.StringVar(&loggingLevelValue, "loggingLevel", "info", "logging level: debug, info, warn, or error")
	flag.StringVar(&loggingLevelValue, "l", "info", "logging level: debug, info, warn, or error")
	flag.Parse()

	loggingLevel, err := httpapi.ParseLoggingLevel(loggingLevelValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --loggingLevel %q: %v\n", loggingLevelValue, err)
		os.Exit(2)
	}
	httpapi.SetLoggingLevel(loggingLevel)

	cfg := httpapi.DefaultConfig("http://localhost:8080")
	configPath := os.Getenv("AGGREGATOR_CONFIG")
	if configPath == "" {
		configPath = "aggregator.config.json"
	}
	cfg, err = httpapi.LoadOptionalConfigFile(configPath, cfg)
	if err != nil {
		httpapi.LogFatalf("load config %s: %v", configPath, err)
	}
	aggregator := httpapi.NewServer(cfg)
	httpServer := &http.Server{
		Addr:    cfg.ListenAddr(),
		Handler: aggregator.Routes(),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	httpapi.LogInfof("aggregator server listening on %s (public base URL %s)", cfg.LocalURL(), cfg.BaseURL)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpapi.LogFatalf("%v", err)
		}
	}()

	<-stop
	if err := aggregator.Shutdown(); err != nil {
		httpapi.LogWarnf("aggregator AS cleanup failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		httpapi.LogFatalf("%v", err)
	}
}
