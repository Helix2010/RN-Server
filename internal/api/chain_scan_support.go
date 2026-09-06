package api

import (
	"context"
	"database/sql"
	"encoding/json"
)

// NetworkChainID 给 indexer 用的链目录查询：id → chainId。
func NetworkChainID(chain string) (int64, bool) {
	chainID, ok := supportedNetwork(chain)
	if !ok {
		return 0, false
	}
	return int64(chainID), true
}

// TenantChainResolver 回答"哪些租户启用了某条链且 onchainSends=true"，规则与 bootstrap
// 下发完全一致（normalizeWallet），indexer 不复制它。
type TenantChainResolver struct{ DB *sql.DB }

// TenantsForChain 返回 chain → 租户 id 列表。没有自己 mobile-bootstrap 行的租户继承
// tenant 0 的钱包段（与 appConfigView 的读法一致）。
func (r *TenantChainResolver) TenantsForChain(ctx context.Context) (map[string][]uint64, error) {
	rows, err := r.DB.QueryContext(ctx, `SELECT t.id, COALESCE(own.config_value, global.config_value) FROM tenants t
		LEFT JOIN app_configs own ON own.tenant_id=t.id AND own.config_key='mobile-bootstrap'
		LEFT JOIN app_configs global ON global.tenant_id=0 AND global.config_key='mobile-bootstrap'
		WHERE t.status=1 AND t.deleted=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]uint64{}
	for rows.Next() {
		var tenant uint64
		var raw []byte
		if err := rows.Scan(&tenant, &raw); err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		wallet := normalizeWallet(object(value["wallet"]))
		if enabled, _ := wallet["onchainSends"].(bool); !enabled {
			continue
		}
		chains, _ := wallet["chains"].([]any)
		for _, item := range chains {
			if chain, ok := item.(string); ok {
				out[chain] = append(out[chain], tenant)
			}
		}
	}
	return out, rows.Err()
}
