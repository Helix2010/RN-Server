package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/indexer"
	"github.com/Helix2010/RN-Server/internal/scan"
)

// 平台级"扫链管理"接口（设计 RN-App docs/design/wallet-receive-index-2026-09-06.md §4.11-4.12）。
// 只对 PLATFORM_ADMIN_USERNAMES 里的账号开放，不按租户过滤：扫链配置与状态是平台级的。

var scanProbeHTTP = &http.Client{Timeout: 45 * time.Second}

// requirePlatformAdmin 在 authenticate() 之后：账号必须在配置文件声明的平台管理员列表里。
func (s *server) requirePlatformAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(s.cfg.PlatformAdminUsernames) == 0 {
			problem(c, 403, "PLATFORM_ADMIN_NOT_CONFIGURED", "PLATFORM_ADMIN_USERNAMES is empty; platform pages are disabled")
			c.Abort()
			return
		}
		if !s.isPlatformAdmin(actor(c)) {
			problem(c, 403, "PLATFORM_ADMIN_REQUIRED", "This account is not a platform administrator")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *server) isPlatformAdmin(name string) bool {
	for _, allowed := range s.cfg.PlatformAdminUsernames {
		if allowed == name {
			return true
		}
	}
	return false
}

// ---- 视图 ----

type scanEndpointView struct {
	Label      string `json:"label"`
	URLMasked  string `json:"urlMasked"`
	URLHash    string `json:"urlHash"`
	HasSecret  bool   `json:"hasSecret"`
	RPS        int    `json:"rps"`
	MaxLogSpan int    `json:"maxLogSpan"`
}

type scanConfigView struct {
	Enabled       bool               `json:"enabled"`
	Paused        bool               `json:"paused"`
	Endpoints     []scanEndpointView `json:"endpoints"`
	MaxLogSpan    int                `json:"maxLogSpan"`
	Confirmations int                `json:"confirmations"`
	PollSeconds   int                `json:"pollSeconds"`
	AddrChunk     int                `json:"addrChunk"`
	NativeMode    string             `json:"nativeMode"`
	NativeGapCap  uint64             `json:"nativeGapCap"`
	StartBlock    uint64             `json:"startBlock"`
	Version       int                `json:"version"`
}

func urlHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func scanConfigViewOf(cfg scan.ChainConfig) scanConfigView {
	view := scanConfigView{Enabled: cfg.Enabled, Paused: cfg.Paused, MaxLogSpan: cfg.MaxLogSpan, Confirmations: cfg.Confirmations, PollSeconds: cfg.PollSeconds,
		AddrChunk: cfg.AddrChunk, NativeMode: string(cfg.NativeMode), NativeGapCap: cfg.NativeGapCap, StartBlock: cfg.StartBlock, Version: cfg.Version, Endpoints: []scanEndpointView{}}
	for _, endpoint := range cfg.Endpoints {
		view.Endpoints = append(view.Endpoints, scanEndpointView{Label: endpoint.Label, URLMasked: scan.MaskURL(endpoint.URL), URLHash: urlHash(endpoint.URL), HasSecret: scan.HasSecret(endpoint.URL), RPS: endpoint.RPS, MaxLogSpan: endpoint.MaxLogSpan})
	}
	return view
}

type scanStateView struct {
	ScannedToBlock uint64                `json:"scannedToBlock"`
	ScannedToTime  *string               `json:"scannedToTime"`
	ScannedToHash  string                `json:"scannedToHash"`
	HeadBlock      uint64                `json:"headBlock"`
	LagBlocks      uint64                `json:"lagBlocks"`
	State          string                `json:"state"`
	LeaseOwner     string                `json:"leaseOwner"`
	LeaseUntil     *string               `json:"leaseUntil"`
	LastError      string                `json:"lastError"`
	ErrorCount     int                   `json:"errorCount"`
	ReorgCount     int                   `json:"reorgCount"`
	EndpointHealth []scan.EndpointHealth `json:"endpointHealth"`
	Jobs           []scan.Job            `json:"jobs"`
	OpenAlerts     []scan.Alert          `json:"openAlerts"`
	UpdatedAt      string                `json:"updatedAt"`
}

func scanStateViewOf(state scan.ChainState) scanStateView {
	view := scanStateView{ScannedToBlock: state.ScannedToBlock, ScannedToHash: state.ScannedToHash, HeadBlock: state.HeadBlock, State: string(state.State), LeaseOwner: state.LeaseOwner,
		LastError: state.LastError, ErrorCount: state.ErrorCount, ReorgCount: state.ReorgCount, EndpointHealth: state.EndpointHealth, Jobs: state.Jobs, OpenAlerts: state.OpenAlerts, UpdatedAt: iso(state.UpdatedAt)}
	if state.ScannedToTime != nil {
		text := iso(*state.ScannedToTime)
		view.ScannedToTime = &text
	}
	if state.HeadBlock > state.ScannedToBlock {
		view.LagBlocks = state.HeadBlock - state.ScannedToBlock
	}
	if state.LeaseUntil != nil {
		until := iso(*state.LeaseUntil)
		view.LeaseUntil = &until
	}
	if view.EndpointHealth == nil {
		view.EndpointHealth = []scan.EndpointHealth{}
	}
	if view.Jobs == nil {
		view.Jobs = []scan.Job{}
	}
	if view.OpenAlerts == nil {
		view.OpenAlerts = []scan.Alert{}
	}
	return view
}

type scanStatsView struct {
	Rows24h          int `json:"rows24h"`
	UnattributedOpen int `json:"unattributedOpen"`
	Watched          int `json:"watched"`
	Tenants          int `json:"tenants"`
}

func (s *server) scanStats(ctx context.Context, chain string, tenants []uint64) (scanStatsView, error) {
	var stats scanStatsView
	since := time.Now().UTC().Add(-24 * time.Hour)
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_transfer_index WHERE chain=? AND created_at>=? AND status='confirmed'`, chain, since).Scan(&stats.Rows24h); err != nil {
		return stats, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_transfer_index WHERE chain=? AND attribution='unattributed' AND status='confirmed'`, chain).Scan(&stats.UnattributedOpen); err != nil {
		return stats, err
	}
	stats.Tenants = len(tenants)
	if len(tenants) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(tenants)), ",")
		args := make([]any, 0, len(tenants))
		for _, tenant := range tenants {
			args = append(args, tenant)
		}
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_user WHERE status='active' AND tenant_id IN (`+placeholders+`)`, args...).Scan(&stats.Watched); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

// scanChains GET /v1/admin/platform/scan/chains：目录 × 配置 × 状态 × 统计。
func (s *server) scanChains(c *gin.Context) {
	ctx := c.Request.Context()
	configs, broken, err := scan.LoadConfigs(ctx, s.db, s.secrets)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load chain scan configs")
		return
	}
	states, err := scan.LoadStates(ctx, s.db)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load chain scan states")
		return
	}
	resolver := &TenantChainResolver{DB: s.db}
	tenantsByChain, err := resolver.TenantsForChain(ctx)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to resolve tenant chains")
		return
	}
	items := []gin.H{}
	for _, network := range supportedNetworks {
		item := gin.H{"chain": network.ID, "name": network.Name, "chainId": network.ChainID, "testnet": network.Testnet, "config": nil, "state": nil, "configError": ""}
		if cfg, ok := configs[network.ID]; ok {
			item["config"] = scanConfigViewOf(cfg)
		}
		if err, ok := broken[network.ID]; ok {
			item["configError"] = err.Error()
		}
		if state, ok := states[network.ID]; ok {
			item["state"] = scanStateViewOf(state)
		}
		stats, err := s.scanStats(ctx, network.ID, tenantsByChain[network.ID])
		if err != nil {
			problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load chain scan stats")
			return
		}
		item["stats"] = stats
		items = append(items, item)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items, "allowPlainHttp": s.cfg.IndexerAllowPlainHTTP, "defaults": gin.H{"addrChunk": scan.DefaultAddrChunk, "nativeGapCap": scan.DefaultNativeGapCap}})
}

// scanEndpointInput 保存 / 体检时的端点：url 为空且 urlHash 命中现有端点时沿用已存的 URL。
type scanEndpointInput struct {
	URL        string `json:"url"`
	URLHash    string `json:"urlHash"`
	Label      string `json:"label"`
	RPS        int    `json:"rps"`
	MaxLogSpan int    `json:"maxLogSpan"`
}

// resolveEndpoints 把输入的端点合成完整配置：没给明文的按 urlHash 从现有配置里取。
func resolveEndpoints(inputs []scanEndpointInput, current []scan.Endpoint) ([]scan.Endpoint, error) {
	stored := map[string]string{}
	for _, endpoint := range current {
		stored[urlHash(endpoint.URL)] = endpoint.URL
	}
	out := make([]scan.Endpoint, 0, len(inputs))
	for index, input := range inputs {
		url := strings.TrimSpace(input.URL)
		if url == "" {
			existing, ok := stored[strings.TrimSpace(input.URLHash)]
			if !ok {
				return nil, &scan.ValidationError{Msg: fmt.Sprintf("端点 %d：没有 url，也没有对应现有端点的 urlHash", index+1)}
			}
			url = existing
		}
		out = append(out, scan.Endpoint{URL: url, Label: strings.TrimSpace(input.Label), RPS: input.RPS, MaxLogSpan: input.MaxLogSpan})
	}
	return out, nil
}

type scanConfigInput struct {
	Enabled       bool                `json:"enabled"`
	Paused        bool                `json:"paused"`
	Endpoints     []scanEndpointInput `json:"endpoints"`
	MaxLogSpan    int                 `json:"maxLogSpan"`
	Confirmations int                 `json:"confirmations"`
	PollSeconds   int                 `json:"pollSeconds"`
	AddrChunk     int                 `json:"addrChunk"`
	NativeMode    string              `json:"nativeMode"`
	NativeGapCap  uint64              `json:"nativeGapCap"`
	StartBlock    uint64              `json:"startBlock"`
}

func (s *server) scanChainParam(c *gin.Context) (evmNetwork, bool) {
	network, ok := platformNetwork(strings.TrimSpace(c.Param("chain")))
	if !ok {
		problem(c, 400, "INVALID_SCAN_REQUEST", fmt.Sprintf("不支持的链 %q：当前平台支持 %s", c.Param("chain"), supportedNetworkIDs()))
		return evmNetwork{}, false
	}
	return network, true
}

func (s *server) currentScanConfig(ctx context.Context, chain string) (scan.ChainConfig, bool, error) {
	cfg, err := scan.LoadConfig(ctx, s.db, chain, s.secrets)
	if errors.Is(err, sql.ErrNoRows) {
		return scan.ChainConfig{}, false, nil
	}
	if err != nil {
		return scan.ChainConfig{}, false, err
	}
	return cfg, true, nil
}

// saveScanChain PUT /v1/admin/platform/scan/chains/:chain
func (s *server) saveScanChain(c *gin.Context) {
	network, ok := s.scanChainParam(c)
	if !ok {
		return
	}
	var body struct {
		ExpectedVersion int             `json:"expectedVersion"`
		Reason          string          `json:"reason"`
		Config          scanConfigInput `json:"config"`
	}
	if err := decode(c, &body); err != nil {
		problem(c, 400, "INVALID_SCAN_REQUEST", "expectedVersion, reason and config are required")
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		problem(c, 400, "INVALID_SCAN_REQUEST", "reason is required")
		return
	}
	ctx := c.Request.Context()
	current, exists, err := s.currentScanConfig(ctx, network.ID)
	if err != nil {
		// 现有行损坏也允许覆盖保存（这是修复途径），但端点必须给明文
		if !errors.Is(err, sql.ErrNoRows) {
			current, exists = scan.ChainConfig{}, true
		}
	}
	endpoints, err := resolveEndpoints(body.Config.Endpoints, current.Endpoints)
	if err != nil {
		problem(c, 400, "INVALID_SCAN_CONFIG", err.Error())
		return
	}
	cfg := scan.ChainConfig{Chain: network.ID, Enabled: body.Config.Enabled, Paused: body.Config.Paused, Endpoints: endpoints, MaxLogSpan: body.Config.MaxLogSpan,
		Confirmations: body.Config.Confirmations, PollSeconds: body.Config.PollSeconds, AddrChunk: body.Config.AddrChunk, NativeMode: scan.NativeMode(body.Config.NativeMode),
		NativeGapCap: body.Config.NativeGapCap, StartBlock: body.Config.StartBlock}
	if err := scan.Validate(cfg, s.cfg.IndexerAllowPlainHTTP); err != nil {
		problem(c, 400, "INVALID_SCAN_CONFIG", err.Error())
		return
	}
	if cfg.Enabled {
		// 启用前每个端点核对 eth_chainId：指错链的端点永远不该存进启用中的配置
		for index, endpoint := range cfg.Endpoints {
			if err := verifyEndpointChain(ctx, int64(network.ChainID), endpoint); err != nil {
				problem(c, 400, "INVALID_SCAN_CONFIG", fmt.Sprintf("端点 %d（%s）：%v", index+1, endpoint.Label, err))
				return
			}
		}
	}
	if !exists && body.ExpectedVersion != 0 {
		problem(c, 409, "SCAN_CONFIG_VERSION_CONFLICT", "this chain has no config yet; expectedVersion must be 0")
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "SCAN_SAVE_FAILED", "Unable to save chain scan config")
		return
	}
	defer tx.Rollback()
	version, err := scan.SaveConfig(ctx, tx, cfg, body.ExpectedVersion, actor(c), s.secrets)
	if errors.Is(err, scan.ErrVersionConflict) {
		problem(c, 409, "SCAN_CONFIG_VERSION_CONFLICT", "Chain scan config was modified by someone else; reload and retry")
		return
	}
	if err != nil {
		problem(c, 500, "SCAN_SAVE_FAILED", "Unable to save chain scan config")
		return
	}
	summary := map[string]any{"enabled": cfg.Enabled, "paused": cfg.Paused, "endpoints": len(cfg.Endpoints), "maxLogSpan": cfg.MaxLogSpan, "confirmations": cfg.Confirmations,
		"pollSeconds": cfg.PollSeconds, "nativeMode": cfg.NativeMode, "startBlock": cfg.StartBlock, "versionBefore": body.ExpectedVersion, "versionAfter": version}
	if err := insertAudit(ctx, tx, newAudit("0", actor(c), "chain_scan.config_saved", "chain", network.ID, strings.TrimSpace(body.Reason), requestID(c), summary)); err != nil {
		problem(c, 500, "SCAN_SAVE_FAILED", "Unable to save chain scan config")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, 500, "SCAN_SAVE_FAILED", "Unable to save chain scan config")
		return
	}
	cfg.Version = version
	c.JSON(200, gin.H{"chain": network.ID, "config": scanConfigViewOf(cfg), "savedAt": iso(time.Now()), "actorId": actor(c), "requestId": requestID(c)})
}

// verifyEndpointChain 保存时的最小体检：eth_chainId 必须等于目录。
func verifyEndpointChain(ctx context.Context, chainID int64, endpoint scan.Endpoint) error {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool := indexer.NewPool("verify", chainID, []scan.Endpoint{endpoint}, scanProbeHTTP, nil)
	if _, err := pool.BeginRound(probeCtx, 0); err != nil {
		if health := pool.Health(); len(health) == 1 && health[0].LastError != "" {
			return errors.New(health[0].LastError)
		}
		return err
	}
	return nil
}

// probeScanChain POST /v1/admin/platform/scan/chains/:chain/probe
func (s *server) probeScanChain(c *gin.Context) {
	network, ok := s.scanChainParam(c)
	if !ok {
		return
	}
	var body struct {
		Endpoints []scanEndpointInput `json:"endpoints"`
	}
	if err := decode(c, &body); err != nil || len(body.Endpoints) == 0 {
		problem(c, 400, "INVALID_SCAN_REQUEST", "endpoints are required")
		return
	}
	if len(body.Endpoints) > scan.MaxEndpoints {
		problem(c, 400, "INVALID_SCAN_REQUEST", fmt.Sprintf("端点最多 %d 个", scan.MaxEndpoints))
		return
	}
	ctx := c.Request.Context()
	current, _, err := s.currentScanConfig(ctx, network.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		current = scan.ChainConfig{}
	}
	endpoints, err := resolveEndpoints(body.Endpoints, current.Endpoints)
	if err != nil {
		problem(c, 400, "INVALID_SCAN_CONFIG", err.Error())
		return
	}
	for index := range endpoints {
		if endpoints[index].RPS < 1 {
			endpoints[index].RPS = 4
		}
	}
	tokens, err := (&indexer.SQLStore{DB: s.db}).Tokens(ctx, network.ID)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load token catalog")
		return
	}
	results := make([]indexer.EndpointProbe, 0, len(endpoints))
	suggestedSpan, suggestedMode, suggestedConfs := 0, "", 0
	for _, endpoint := range endpoints {
		probeCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		result := indexer.ProbeEndpoint(probeCtx, int64(network.ChainID), endpoint, tokens, scanProbeHTTP)
		cancel()
		results = append(results, result)
		if !result.OK {
			continue
		}
		if suggestedSpan == 0 || result.SuggestedSpan < suggestedSpan {
			suggestedSpan = result.SuggestedSpan
		}
		if suggestedMode == "" {
			suggestedMode, suggestedConfs = result.SuggestedMode, result.SuggestedConfs
		}
	}
	c.JSON(200, gin.H{"chain": network.ID, "results": results, "suggestion": gin.H{"maxLogSpan": suggestedSpan, "nativeMode": suggestedMode, "confirmations": suggestedConfs}})
}

// toggleScanChain POST …/pause | …/resume：只翻 paused，走同一套版本与审计。
func (s *server) toggleScanChain(paused bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		network, ok := s.scanChainParam(c)
		if !ok {
			return
		}
		var body struct {
			ExpectedVersion int    `json:"expectedVersion"`
			Reason          string `json:"reason"`
		}
		if err := decode(c, &body); err != nil || strings.TrimSpace(body.Reason) == "" {
			problem(c, 400, "INVALID_SCAN_REQUEST", "expectedVersion and reason are required")
			return
		}
		ctx := c.Request.Context()
		cfg, exists, err := s.currentScanConfig(ctx, network.ID)
		if err != nil || !exists {
			problem(c, 404, "SCAN_CONFIG_NOT_FOUND", "This chain has no scan config")
			return
		}
		cfg.Paused = paused
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			problem(c, 500, "SCAN_SAVE_FAILED", "Unable to update chain scan config")
			return
		}
		defer tx.Rollback()
		version, err := scan.SaveConfig(ctx, tx, cfg, body.ExpectedVersion, actor(c), s.secrets)
		if errors.Is(err, scan.ErrVersionConflict) {
			problem(c, 409, "SCAN_CONFIG_VERSION_CONFLICT", "Chain scan config was modified by someone else; reload and retry")
			return
		}
		if err != nil {
			problem(c, 500, "SCAN_SAVE_FAILED", "Unable to update chain scan config")
			return
		}
		action := "chain_scan.resumed"
		if paused {
			action = "chain_scan.paused"
		}
		if err := insertAudit(ctx, tx, newAudit("0", actor(c), action, "chain", network.ID, strings.TrimSpace(body.Reason), requestID(c), map[string]any{"versionAfter": version})); err != nil {
			problem(c, 500, "SCAN_SAVE_FAILED", "Unable to update chain scan config")
			return
		}
		if err := tx.Commit(); err != nil {
			problem(c, 500, "SCAN_SAVE_FAILED", "Unable to update chain scan config")
			return
		}
		cfg.Version = version
		c.JSON(200, gin.H{"chain": network.ID, "config": scanConfigViewOf(cfg)})
	}
}

// createScanJob POST …/jobs：往 chain_scan_state.jobs 追加一条待执行任务（行锁）。
func (s *server) createScanJob(c *gin.Context) {
	network, ok := s.scanChainParam(c)
	if !ok {
		return
	}
	var body struct {
		Kind      string `json:"kind"`
		FromBlock uint64 `json:"fromBlock"`
		ToBlock   uint64 `json:"toBlock"`
		Reason    string `json:"reason"`
	}
	if err := decode(c, &body); err != nil || strings.TrimSpace(body.Reason) == "" {
		problem(c, 400, "INVALID_SCAN_REQUEST", "kind, fromBlock, toBlock and reason are required")
		return
	}
	kind := scan.JobKind(strings.TrimSpace(body.Kind))
	if kind != scan.JobRescan && kind != scan.JobAttribute {
		problem(c, 400, "INVALID_SCAN_REQUEST", "kind must be rescan or attribute")
		return
	}
	if body.FromBlock == 0 || body.ToBlock < body.FromBlock || body.ToBlock-body.FromBlock > 5_000_000 {
		problem(c, 400, "INVALID_SCAN_REQUEST", "fromBlock/toBlock must form a range of at most 5,000,000 blocks")
		return
	}
	ctx := c.Request.Context()
	job := scan.Job{ID: "job_" + randomID(12), Kind: kind, FromBlock: body.FromBlock, ToBlock: body.ToBlock, ProgressBlock: body.FromBlock - 1, State: scan.JobPending,
		CreatedBy: actor(c), Reason: strings.TrimSpace(body.Reason), CreatedAt: time.Now().UTC()}
	err := s.mutateScanJobs(ctx, network.ID, func(jobs []scan.Job) ([]scan.Job, error) {
		if len(jobs) >= 20 {
			return nil, errors.New("too many pending jobs on this chain")
		}
		return append(jobs, job), nil
	}, "chain_scan.job_created", job.Reason, requestID(c), actor(c), map[string]any{"jobId": job.ID, "kind": kind, "fromBlock": job.FromBlock, "toBlock": job.ToBlock})
	if err != nil {
		s.writeScanJobProblem(c, err)
		return
	}
	c.JSON(200, gin.H{"chain": network.ID, "job": job})
}

// cancelScanJob POST …/jobs/:id/cancel
func (s *server) cancelScanJob(c *gin.Context) {
	network, ok := s.scanChainParam(c)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(c, &body); err != nil || strings.TrimSpace(body.Reason) == "" {
		problem(c, 400, "INVALID_SCAN_REQUEST", "reason is required")
		return
	}
	jobID := strings.TrimSpace(c.Param("id"))
	err := s.mutateScanJobs(c.Request.Context(), network.ID, func(jobs []scan.Job) ([]scan.Job, error) {
		kept := jobs[:0]
		found := false
		for _, job := range jobs {
			if job.ID == jobID {
				found = true
				continue
			}
			kept = append(kept, job)
		}
		if !found {
			return nil, errScanJobNotFound
		}
		return kept, nil
	}, "chain_scan.job_cancelled", strings.TrimSpace(body.Reason), requestID(c), actor(c), map[string]any{"jobId": jobID})
	if err != nil {
		s.writeScanJobProblem(c, err)
		return
	}
	c.JSON(200, gin.H{"chain": network.ID, "cancelled": jobID})
}

var errScanJobNotFound = errors.New("job not found")
var errScanStateNotFound = errors.New("chain has no scan state yet")

func (s *server) writeScanJobProblem(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errScanJobNotFound):
		problem(c, 404, "SCAN_JOB_NOT_FOUND", "No such job on this chain")
	case errors.Is(err, errScanStateNotFound):
		problem(c, 409, "SCAN_STATE_NOT_FOUND", "The indexer has not initialised this chain yet")
	default:
		problem(c, 500, "SCAN_SAVE_FAILED", err.Error())
	}
}

// mutateScanJobs 行锁下改 jobs JSON，并写审计。
func (s *server) mutateScanJobs(ctx context.Context, chain string, mutate func([]scan.Job) ([]scan.Job, error), action, reason, request, who string, summary map[string]any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT jobs FROM chain_scan_state WHERE chain=? FOR UPDATE`, chain).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errScanStateNotFound
		}
		return err
	}
	var jobs []scan.Job
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &jobs); err != nil {
			return fmt.Errorf("chain_scan_state.%s jobs: %w", chain, err)
		}
	}
	next, err := mutate(jobs)
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(next)
	if string(encoded) == "null" {
		encoded = []byte("[]")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chain_scan_state SET jobs=?,updated_at=? WHERE chain=?`, encoded, time.Now().UTC(), chain); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, newAudit("0", who, action, "chain", chain, reason, request, summary)); err != nil {
		return err
	}
	return tx.Commit()
}

// scanTransfers GET /v1/admin/platform/scan/transfers?chain=&address= 客服查询。
func (s *server) scanTransfers(c *gin.Context) {
	chain := strings.TrimSpace(c.Query("chain"))
	address := strings.ToLower(strings.TrimSpace(c.Query("address")))
	if _, ok := platformNetwork(chain); !ok || !addressPattern.MatchString(address) {
		problem(c, 400, "INVALID_SCAN_REQUEST", "chain must be a catalog chain and address a 0x address")
		return
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT tenant_id,direction,asset,contract_address,CAST(amount_raw AS CHAR),counterparty,tx_hash,log_index,block_number,block_hash,block_time,attribution,gap_from_block,status,created_at FROM wallet_transfer_index WHERE chain=? AND address_key=? ORDER BY block_number DESC,id DESC LIMIT 200`, chain, address)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load transfers")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var tenant uint64
		var direction, asset, contract, amount, counterparty, txHash, blockHash, attribution, status string
		var logIndex int
		var blockNumber uint64
		var gap sql.NullInt64
		var blockTime, created time.Time
		if err := rows.Scan(&tenant, &direction, &asset, &contract, &amount, &counterparty, &txHash, &logIndex, &blockNumber, &blockHash, &blockTime, &attribution, &gap, &status, &created); err != nil {
			problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load transfers")
			return
		}
		item := gin.H{"tenantId": fmt.Sprint(tenant), "chain": chain, "addressKey": address, "direction": direction, "asset": asset, "contractAddress": contract, "amountRaw": amount, "counterparty": counterparty,
			"txHash": txHash, "logIndex": logIndex, "blockNumber": blockNumber, "blockHash": blockHash, "blockTime": iso(blockTime), "attribution": attribution, "status": status, "createdAt": iso(created), "gapFromBlock": nil}
		if gap.Valid {
			item["gapFromBlock"] = gap.Int64
		}
		items = append(items, item)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}

// tenantIndexStatus GET /v1/admin/wallet/index-status：租户视角的只读状态。
func (s *server) tenantIndexStatus(c *gin.Context) {
	ctx := c.Request.Context()
	view, err := s.appConfigView(ctx, tenantID(c))
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load tenant config")
		return
	}
	wallet := object(object(view["config"])["wallet"])
	onchain, _ := wallet["onchainSends"].(bool)
	states, err := scan.LoadStates(ctx, s.db)
	if err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to load chain scan states")
		return
	}
	var watched int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_user WHERE tenant_id=? AND status='active'`, tenantID(c)).Scan(&watched); err != nil {
		problem(c, 500, "SCAN_QUERY_FAILED", "Unable to count wallet users")
		return
	}
	since := time.Now().UTC().Add(-24 * time.Hour)
	items := []gin.H{}
	chains, _ := wallet["chains"].([]any)
	for _, raw := range chains {
		chain, _ := raw.(string)
		item := gin.H{"chain": chain, "indexed": onchain, "state": "unconfigured", "lagBlocks": 0, "headBlock": 0, "scannedToBlock": 0, "scannedToTime": nil, "rows24h": 0, "updatedAt": nil}
		if state, ok := states[chain]; ok && onchain {
			item["state"] = string(state.State)
			item["headBlock"] = state.HeadBlock
			item["scannedToBlock"] = state.ScannedToBlock
			if state.ScannedToTime != nil {
				item["scannedToTime"] = iso(*state.ScannedToTime)
			}
			if state.HeadBlock > state.ScannedToBlock {
				item["lagBlocks"] = state.HeadBlock - state.ScannedToBlock
			}
			item["updatedAt"] = iso(state.UpdatedAt)
			var rows int
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_transfer_index WHERE tenant_id=? AND chain=? AND created_at>=? AND status='confirmed'`, tenantID(c), chain, since).Scan(&rows); err == nil {
				item["rows24h"] = rows
			}
		}
		items = append(items, item)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"onchainSends": onchain, "watched": watched, "chains": items})
}
