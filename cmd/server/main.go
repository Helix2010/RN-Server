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
	if len(os.Args) == 3 && os.Args[1] == "push-credentials" && os.Args[2] == "import-env" {
		if err := importPushCredentialsFromEnv(cfg, database); err != nil {
			slog.Error("cannot import push credentials from the env file", "error", err)
			os.Exit(1)
		}
		return
	}
	// 给指纹功能上线之前构建的安装包补记原生指纹。只在服务器上跑，不开成接口——
	// 理由写在 recordReleaseFingerprint 的注释里。
	if len(os.Args) == 6 && os.Args[1] == "release-fingerprint" {
		if err := recordReleaseFingerprint(database, os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			slog.Error("cannot record the native fingerprint", "error", err)
			os.Exit(1)
		}
		return
	}
	// 平台管理员账号的建号与找回：控制台里没有可用的平台管理员时只能在服务器上做（platform_account.go）
	if len(os.Args) >= 3 && os.Args[1] == "admin" && os.Args[2] == "platform-account" {
		if err := runPlatformAccountCommand(cfg, database, os.Args[3:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "platform-account:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "indexer" {
		runIndexer(cfg, database)
		return
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	// 打包任务回收是服务端自己的定时器（每分钟），不挂在构建机认领上：签名闸挂了，
	// signing 的任务要退回待签名，而这和有没有构建机在轮询无关（见 api/build_reaper.go）
	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		api.RunBuildJobReaper(workerCtx, cfg, database)
	}()
	if cfg.PushDispatchEnabled {
		// 推送凭据按租户存在库里，用主密钥封着；派发器要能解开它们才能发出去
		box, boxErr := secretbox.New(cfg.StorageMasterKey)
		if boxErr != nil {
			slog.Error("push dispatcher cannot decrypt per-tenant credentials", "error", boxErr)
			os.Exit(1)
		}
		dispatcher, dispatchErr := push.New(workerCtx, database.DB, cfg, box)
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
	// 回收循环随服务关闭退出；等它把手上这一轮做完，不在事务中途断开连接
	workerCancel()
	<-reaperDone
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

// runIndexer 是 `./rn-server indexer`：扫链进程。
//
// 这个子命令**默认就扫**：跑它就是要扫链。空转等信号那套是给 Docker Compose 防
// 容器反复重启设计的，裸机部署下不想扫就不启那个 unit，不必启一个 unit 再让它
// 什么都不做。所以 INDEXER_ENABLED 在这里的默认值是 true，只有显式写 false 才
// 空转——留着这条是因为容器部署还在用它。
func runIndexer(cfg config.Config, database *store.Store) {
	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !cfg.IndexerEnabledFor("indexer") {
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
