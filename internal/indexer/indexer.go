package indexer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

const (
	// reloadInterval 多久重读一次 chain-scan.* 配置行。
	reloadInterval = 30 * time.Second
)

// Catalog 回答链目录：id → chainId。规则在 api 包（supportedNetworks），这里只接函数。
type Catalog func(chain string) (int64, bool)

// Runner 管理全部链的 worker：按配置版本启停、坏配置标 unconfigured。
type Runner struct {
	DB      *sql.DB
	Box     *secretbox.Box
	Store   Store
	Tenants TenantResolver
	Catalog Catalog
	Log     *slog.Logger
	Client  *http.Client
	Owner   string

	mu      sync.Mutex
	workers map[string]*running
}

type running struct {
	version int
	paused  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// Run 循环到 ctx 取消。
func (r *Runner) Run(ctx context.Context) {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Owner == "" {
		host, _ := os.Hostname()
		r.Owner = fmt.Sprintf("%s/%d", host, os.Getpid())
	}
	r.workers = map[string]*running{}
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for {
		r.reload(ctx)
		select {
		case <-ctx.Done():
			r.stopAll()
			return
		case <-ticker.C:
		}
	}
}

// reload 读配置，启停 worker。
func (r *Runner) reload(ctx context.Context) {
	configs, broken, err := scan.LoadConfigs(ctx, r.DB, r.Box)
	if err != nil {
		r.Log.Error("load chain scan configs failed", "error", err)
		return
	}
	for chain, err := range broken {
		r.Log.Error("chain scan config is broken; chain stays unconfigured", "chain", chain, "error", err)
		r.stop(chain)
		r.markUnconfigured(ctx, chain, err.Error())
	}
	r.mu.Lock()
	active := map[string]bool{}
	r.mu.Unlock()
	for chain, cfg := range configs {
		chainID, known := r.Catalog(chain)
		if !known {
			r.Log.Error("chain scan config refers to a chain outside the catalog", "chain", chain)
			r.stop(chain)
			r.markUnconfigured(ctx, chain, "chain is not in the platform catalog")
			continue
		}
		if !cfg.Enabled {
			r.stop(chain)
			r.markUnconfigured(ctx, chain, "")
			continue
		}
		active[chain] = true
		r.mu.Lock()
		current, exists := r.workers[chain]
		r.mu.Unlock()
		if exists && current.version == cfg.Version {
			continue
		}
		r.stop(chain)
		r.start(ctx, cfg, chainID)
	}
	r.mu.Lock()
	for chain := range r.workers {
		if !active[chain] {
			delete(r.workers, chain)
		}
	}
	r.mu.Unlock()
}

func (r *Runner) start(ctx context.Context, cfg scan.ChainConfig, chainID int64) {
	pool := NewPool(cfg.Chain, chainID, cfg.Endpoints, r.Client, nil)
	worker := NewWorker(cfg, pool, r.Store, r.Tenants, r.Owner, nil, r.Log)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.mu.Lock()
	r.workers[cfg.Chain] = &running{version: cfg.Version, paused: cfg.Paused, cancel: cancel, done: done}
	r.mu.Unlock()
	r.Log.Info("chain worker started", "chain", cfg.Chain, "version", cfg.Version, "endpoints", len(cfg.Endpoints), "nativeMode", cfg.NativeMode, "paused", cfg.Paused)
	go func() {
		defer close(done)
		worker.Run(workerCtx)
	}()
}

func (r *Runner) stop(chain string) {
	r.mu.Lock()
	current, exists := r.workers[chain]
	if exists {
		delete(r.workers, chain)
	}
	r.mu.Unlock()
	if !exists {
		return
	}
	current.cancel()
	select {
	case <-current.done:
	case <-time.After(30 * time.Second):
		r.Log.Warn("chain worker did not stop in time", "chain", chain)
	}
	r.Log.Info("chain worker stopped", "chain", chain)
}

func (r *Runner) stopAll() {
	r.mu.Lock()
	chains := make([]string, 0, len(r.workers))
	for chain := range r.workers {
		chains = append(chains, chain)
	}
	r.mu.Unlock()
	for _, chain := range chains {
		r.stop(chain)
	}
}

// markUnconfigured 有状态行的链在配置停用 / 损坏时标 unconfigured；没有状态行就不用建。
func (r *Runner) markUnconfigured(ctx context.Context, chain, reason string) {
	state, err := r.Store.LoadState(ctx, chain)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		r.Log.Error("load chain state failed", "chain", chain, "error", err)
		return
	}
	if state.State == scan.StateUnconfigured && state.LastError == reason {
		return
	}
	state.State = scan.StateUnconfigured
	state.LastError = reason
	if err := r.Store.SaveState(ctx, state); err != nil {
		r.Log.Error("save chain state failed", "chain", chain, "error", err)
	}
}
