package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zephrfish/sandboxspy/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	var (
		configFile = flag.String("config", "server_config.json", "Path to configuration file")
		version    = flag.Bool("version", false, "Show version information")
		debug      = flag.Bool("debug", false, "Enable debug logging")
	)
	
	flag.Parse()
	
	if *version {
		fmt.Printf("SandboxSpy Server\nVersion: %s\nBuild Time: %s\n", Version, BuildTime)
		os.Exit(0)
	}
	
	// Setup logging
	logger := logrus.New()
	if *debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	
	logger.WithFields(logrus.Fields{
		"version":    Version,
		"build_time": BuildTime,
	}).Info("Starting SandboxSpy Server")
	
	// Load configuration
	config, err := server.LoadConfig(*configFile)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}
	
	// Create server instance
	srv := server.New(config, logger)
	
	// Initialize server
	if err := srv.Initialize(); err != nil {
		logger.WithError(err).Fatal("Failed to initialize server")
	}
	
	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		logger.Info("Shutdown signal received")
		cancel()
	}()
	
	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start(ctx)
	}()
	
	// Wait for shutdown or error
	select {
	case err := <-serverErr:
		if err != nil {
			logger.WithError(err).Error("Server error")
		}
	case <-ctx.Done():
		logger.Info("Shutting down server...")
		
		// Give server time to shutdown gracefully
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.WithError(err).Error("Failed to shutdown server gracefully")
		}
	}
	
	logger.Info("Server stopped")
}

func init() {
	// Set up default logger
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}