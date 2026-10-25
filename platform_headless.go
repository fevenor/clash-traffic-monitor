//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// runPlatform keeps the historical headless behavior on Linux, macOS and in
// containers: start the application, wait for SIGINT/SIGTERM or a server error,
// then shut down exactly once.
func runPlatform() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	app, err := newApplication(cfg, defaultDatabasePath())
	if err != nil {
		return err
	}

	app.start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-app.errors():
		log.Printf("server error: %v", err)
		if shutdownErr := app.shutdown(); shutdownErr != nil {
			log.Printf("shutdown after server error: %v", shutdownErr)
		}
		return err
	case <-sigCh:
	}

	return app.shutdown()
}

func reportPlatformFatal(err error) {
	log.Printf("fatal: %v", err)
}
