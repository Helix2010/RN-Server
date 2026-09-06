package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/internal/api"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/indexer"
	"github.com/Helix2010/RN-Server/internal/push"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/internal/store"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			slog.Error("healthcheck failed", "error", err)
			os.Exit(1)
		}
		return
	}
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	database, err := store.Open(cfg)
	if err != nil {
		slog.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	if len(os.Args) == 2 && os.Args[1] == "migrate" {
		if err := database.Migrate(cfg); err != nil {
			slog.Error("database migration failed", "error", err)
			os.Exit(1)
		}
		slog.Info("database migrations complete")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "indexer" {
		runIndexer(cfg, database)
		return
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	if cfg.PushDispatchEnabled {
		dispatcher, dispatchErr := push.New(workerCtx, database.DB, cfg)
		if dispatchErr != nil {
			slog.Error("push dispatcher initialization failed", "error", dispatchErr)
			os.Exit(1)
		}
		go dispatcher.Run(workerCtx)
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           api.New(cfg, database),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.HTTPReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.HTTPWriteTimeout) * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	go func() {
		slog.Info("RN-Server listening", "port", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-shutdown.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
}

func healthcheck() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + "/health/ready")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected readiness status: %d", response.StatusCode)
	}
	return nil
}

// runIndexer 是 `./rn-server indexer`：扫链进程。INDEXER_ENABLED=false 时空转等信号，
// 容器不会因为进程退出而反复重启；开关翻到 true 要重启进程。
func runIndexer(cfg config.Config, database *store.Store) {
	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !cfg.IndexerEnabled {
		slog.Info("indexer is disabled (INDEXER_ENABLED=false); idling until signal")
		<-shutdown.Done()
		return
	}
	box, err := secretbox.New(cfg.StorageMasterKey)
	if err != nil {
		slog.Error("indexer cannot decrypt scan endpoints", "error", err)
		os.Exit(1)
	}
	runner := &indexer.Runner{
		DB:      database.DB,
		Box:     box,
		Store:   &indexer.SQLStore{DB: database.DB},
		Tenants: &api.TenantChainResolver{DB: database.DB},
		Catalog: api.NetworkChainID, AlertWebhook: cfg.IndexerAlertWebhook,
		Log: slog.Default(),
	}
	slog.Info("indexer starting")
	runner.Run(shutdown)
	slog.Info("indexer stopped")
}
