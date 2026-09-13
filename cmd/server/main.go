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
	// `rn-server config` 不连库：配置有问题的时候多半正是连不上库的时候
	if len(os.Args) == 2 && os.Args[1] == "config" {
		printConfig(cfg)
		return
	}
	// 旧的十一个 MYSQL_* 键还认，但每次启动都说一次，并把等价的那一行直接给出来
	// ——运维照抄进 env 就完成了迁移。代码和 env 是分别部署的，只认 DSN 会让
	// "代码先到"的那次部署红掉。
	if cfg.MySQLSource != "MYSQL_DSN" {
		slog.Warn("MYSQL_HOST/PORT/USER/PASSWORD/DATABASE and friends are deprecated; put this one line in the env file as MYSQL_DSN (with the real password) and delete the eleven keys",
			"equivalent", cfg.RedactedMySQLDSN())
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
		Addr:              cfg.BindAddress + ":" + cfg.Port,
		Handler:           api.New(cfg, database),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.HTTPReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.HTTPWriteTimeout) * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	go func() {
		slog.Info("RN-Server listening", "address", cfg.BindAddress+":"+cfg.Port)
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
		Store:   &indexer.SQLStore{DB: database.DB, ChainName: api.NetworkName},
		Tenants: &api.TenantChainResolver{DB: database.DB},
		Catalog: api.NetworkChainID, AlertWebhook: cfg.IndexerAlertWebhook,
		Log: slog.Default(),
	}
	slog.Info("indexer starting")
	runner.Run(shutdown)
	slog.Info("indexer stopped")
}
