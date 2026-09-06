package api

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/scan"
)

// 移动端的链上转账记录（设计 wallet-receive-index-2026-09-06 §4.11）。
// 记录来自 wallet_transfer_index（唯一正式来源），只返回 confirmed 行；index 给出
// 租户启用的每条链的索引进度，App 据此显示"已索引到 / 未开启 / 中断"，并与本机
// 转出账本按 (chain, txHash) 合并。

const (
	transferPageDefault = 50
	transferPageMax     = 200
)

// transferCursor 键集分页游标：按 (block_number DESC, id DESC) 往后翻。
type transferCursor struct {
	Block uint64
	ID    uint64
}

func encodeTransferCursor(cursor transferCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%d", cursor.Block, cursor.ID)))
}

// decodeTransferCursor 空串表示第一页；坏游标是客户端错误，不悄悄从头翻。
func decodeTransferCursor(raw string) (*transferCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("cursor is not base64url")
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("cursor must be block:id")
	}
	block, blockErr := strconv.ParseUint(parts[0], 10, 64)
	id, idErr := strconv.ParseUint(parts[1], 10, 64)
	if blockErr != nil || idErr != nil || id == 0 {
		return nil, fmt.Errorf("cursor must be block:id")
	}
	return &transferCursor{Block: block, ID: id}, nil
}

// transferIndexView 一条链的索引进度；state 之外的字段只在有状态行时出现。
type transferIndexView struct {
	State      string  `json:"state"`
	Block      *uint64 `json:"block,omitempty"`
	HeadBlock  *uint64 `json:"headBlock,omitempty"`
	Time       *string `json:"time,omitempty"`
	LagSeconds *int64  `json:"lagSeconds,omitempty"`
}

// transferIndexOf 租户启用的每条链 → 进度。租户没开 onchainSends、链没有状态行或
// 配置已关闭时一律 unconfigured：App 只显示本机转出并说明未开启收款索引。
// lagSeconds = now − 游标区块的链上时间，不用出块时间估算。
func transferIndexOf(chains []string, onchain bool, states map[string]scan.ChainState, now time.Time) map[string]transferIndexView {
	index := map[string]transferIndexView{}
	for _, chain := range chains {
		view := transferIndexView{State: string(scan.StateUnconfigured)}
		if state, ok := states[chain]; ok && onchain && state.State != scan.StateUnconfigured {
			block, head := state.ScannedToBlock, state.HeadBlock
			view = transferIndexView{State: string(state.State), Block: &block, HeadBlock: &head}
			if state.ScannedToTime != nil {
				text := iso(*state.ScannedToTime)
				lag := int64(now.Sub(*state.ScannedToTime) / time.Second)
				if lag < 0 {
					lag = 0
				}
				view.Time, view.LagSeconds = &text, &lag
			}
		}
		index[chain] = view
	}
	return index
}

// transferTokenView 记录对应代币的目录元数据；App 用它显示符号与精度，不自己猜。
type transferTokenView struct {
	Address         string `json:"address"`
	Symbol          string `json:"symbol"`
	Name            string `json:"name"`
	Decimals        int    `json:"decimals"`
	DisplayDecimals int    `json:"displayDecimals"`
	LogoColor       string `json:"logoColor"`
}

// tokenViewsByKey 以 chain|小写合约地址 为键；原生币的键是 chain|native。
func tokenViewsByKey(rows []tokenRecord) map[string]transferTokenView {
	views := map[string]transferTokenView{}
	for _, row := range rows {
		views[row.Chain+"|"+strings.ToLower(row.Address)] = transferTokenView{Address: row.Address, Symbol: row.Symbol, Name: row.Name, Decimals: row.Decimals, DisplayDecimals: row.DisplayDecimals, LogoColor: row.LogoColor}
	}
	return views
}

// walletTransfers GET /v1/mobile/wallet/transfers?chain=&cursor=&limit=
func (s *server) walletTransfers(c *gin.Context) {
	record, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	chain := strings.TrimSpace(c.Query("chain"))
	if chain != "" {
		if _, known := platformNetwork(chain); !known {
			problem(c, 400, "INVALID_TRANSFER_QUERY", "chain must be a catalog chain")
			return
		}
	}
	limit := transferPageDefault
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > transferPageMax {
			problem(c, 400, "INVALID_TRANSFER_QUERY", fmt.Sprintf("limit must be between 1 and %d", transferPageMax))
			return
		}
		limit = parsed
	}
	cursor, err := decodeTransferCursor(c.Query("cursor"))
	if err != nil {
		problem(c, 400, "INVALID_TRANSFER_CURSOR", err.Error())
		return
	}
	tenant := tenantID(c)
	view, err := s.appConfigView(ctx, tenant)
	if err != nil {
		problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load tenant config")
		return
	}
	wallet := object(object(view["config"])["wallet"])
	onchain, _ := wallet["onchainSends"].(bool)
	chains := []string{}
	if raw, _ := wallet["chains"].([]any); raw != nil {
		for _, item := range raw {
			if id, ok := item.(string); ok {
				chains = append(chains, id)
			}
		}
	}
	states, err := scan.LoadStates(ctx, s.db)
	if err != nil {
		problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load chain scan states")
		return
	}
	tokenRows, err := s.queryTokens(ctx, tenant, chain)
	if err != nil {
		problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load token catalog")
		return
	}
	tokens := tokenViewsByKey(mergeTokenRecords(tokenRows))

	query := `SELECT id,chain,direction,asset,contract_address,CAST(amount_raw AS CHAR),counterparty,tx_hash,log_index,block_number,block_time,attribution FROM wallet_transfer_index WHERE tenant_id=? AND address_key=? AND status='confirmed'`
	args := []any{tenant, strings.ToLower(record.Address)}
	if chain != "" {
		query += ` AND chain=?`
		args = append(args, chain)
	}
	if cursor != nil {
		query += ` AND (block_number<? OR (block_number=? AND id<?))`
		args = append(args, cursor.Block, cursor.Block, cursor.ID)
	}
	query += ` ORDER BY block_number DESC,id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load transfers")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	var last transferCursor
	var next any
	for rows.Next() {
		var id, blockNumber uint64
		var rowChain, direction, asset, contract, amount, counterparty, txHash, attribution string
		var logIndex int
		var blockTime time.Time
		if err := rows.Scan(&id, &rowChain, &direction, &asset, &contract, &amount, &counterparty, &txHash, &logIndex, &blockNumber, &blockTime, &attribution); err != nil {
			problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load transfers")
			return
		}
		if len(items) == limit {
			// 多取的那一行只用来判断还有下一页
			next = encodeTransferCursor(last)
			break
		}
		item := gin.H{"chain": rowChain, "direction": direction, "asset": asset, "contractAddress": contract, "amountRaw": amount, "counterparty": counterparty,
			"txHash": txHash, "logIndex": logIndex, "blockNumber": blockNumber, "blockTime": iso(blockTime), "attribution": attribution, "token": nil}
		if token, ok := tokens[rowChain+"|"+strings.ToLower(contract)]; ok {
			item["token"] = token
		}
		items = append(items, item)
		last = transferCursor{Block: blockNumber, ID: id}
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "TRANSFER_QUERY_FAILED", "Unable to load transfers")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items, "nextCursor": next, "index": transferIndexOf(chains, onchain, states, time.Now().UTC())})
}
