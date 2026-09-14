package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 管理端列表页的分页与筛选约定（设计 admin-list-pagination-2026-09-14 §2）。
// 设备、账号、诊断、构建四个列表早于这套约定，各有自己的游标，没有迁过来。

const (
	adminListDefaultLimit = 50
	adminListMaxLimit     = 200
)

// sqlWhere 按 AND 拼接的条件。子句里的列名只来自代码，值一律走占位符。
type sqlWhere struct {
	clauses []string
	args    []any
}

func (w *sqlWhere) add(clause string, args ...any) {
	w.clauses = append(w.clauses, clause)
	w.args = append(w.args, args...)
}

func (w sqlWhere) sql() string {
	if len(w.clauses) == 0 {
		return "TRUE"
	}
	return strings.Join(w.clauses, " AND ")
}

// and 返回两组条件的并集，不改动任何一方：计数用筛选条件，取页还要再加游标条件。
func (w sqlWhere) and(other sqlWhere) sqlWhere {
	return sqlWhere{
		clauses: append(append([]string{}, w.clauses...), other.clauses...),
		args:    append(append([]any{}, w.args...), other.args...),
	}
}

type cursorKind int

const (
	cursorText cursorKind = iota
	cursorUint
	cursorTime
)

// sortKey 一个排序列。列表一律按全部排序列倒序，最后一列必须唯一（主键）。
type sortKey struct {
	column string
	kind   cursorKind
}

// listPage 一页的大小，以及"排在游标那一行之后"的条件（第一页为空）。
type listPage struct {
	limit int
	after sqlWhere
}

// parseListPage 读 limit 与 cursor。坏游标是客户端错误，报出来，不悄悄从第一页翻。
func parseListPage(c *gin.Context, keys ...sortKey) (listPage, string) {
	page := listPage{limit: adminListDefaultLimit}
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > adminListMaxLimit {
			return page, fmt.Sprintf("limit must be between 1 and %d", adminListMaxLimit)
		}
		page.limit = value
	}
	raw := strings.TrimSpace(c.Query("cursor"))
	if raw == "" {
		return page, ""
	}
	values, err := decodeListCursor(raw, keys)
	if err != nil {
		return page, "cursor is invalid"
	}
	columns := make([]string, len(keys))
	for i, key := range keys {
		columns[i] = key.column
	}
	clause, args := keysetBefore(columns, values)
	page.after.add(clause, args...)
	return page, ""
}

// keysetBefore 生成倒序键集的"下一页"条件：
// (a<? OR (a=? AND (b<? OR (b=? AND c<?))))
func keysetBefore(columns []string, values []any) (string, []any) {
	last := len(columns) - 1
	clause := columns[last] + "<?"
	args := []any{values[last]}
	for i := last - 1; i >= 0; i-- {
		clause = "(" + columns[i] + "<? OR (" + columns[i] + "=? AND " + clause + "))"
		args = append([]any{values[i], values[i]}, args...)
	}
	return clause, args
}

// encodeListCursor 游标是 base64url(JSON 字符串数组)。不用 "a:b" 拼接：推送投递的
// 主键里有 installation_id 这种任意字符串，拼接会有歧义。时间存 UnixNano，
// DATETIME(3) 只到毫秒，往返无损。
func encodeListCursor(values ...any) string {
	parts := make([]string, len(values))
	for i, value := range values {
		if at, ok := value.(time.Time); ok {
			parts[i] = strconv.FormatInt(at.UnixNano(), 10)
			continue
		}
		parts[i] = fmt.Sprint(value)
	}
	raw, _ := json.Marshal(parts)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeListCursor(raw string, keys []sortKey) ([]any, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var parts []string
	if err := json.Unmarshal(decoded, &parts); err != nil {
		return nil, err
	}
	if len(parts) != len(keys) {
		return nil, errors.New("cursor has the wrong number of parts")
	}
	values := make([]any, len(parts))
	for i, part := range parts {
		switch keys[i].kind {
		case cursorTime:
			nanos, err := strconv.ParseInt(part, 10, 64)
			if err != nil {
				return nil, err
			}
			values[i] = time.Unix(0, nanos).UTC()
		case cursorUint:
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return nil, err
			}
			values[i] = number
		default:
			if part == "" {
				return nil, errors.New("cursor has an empty part")
			}
			values[i] = part
		}
	}
	return values, nil
}

// finishListPage 查询时多取一行只用来判断有没有下一页；游标指向本页最后一行。
func finishListPage[T any](items []T, cursors []string, limit int) ([]T, any) {
	if len(items) <= limit {
		return items, nil
	}
	return items[:limit], cursors[limit-1]
}

// listResponse total 是当前筛选条件下的真实计数，不是本页条数。
func listResponse(items any, total int, next any, limit int) gin.H {
	return gin.H{"items": items, "total": total, "nextCursor": next, "hasMore": next != nil, "limit": limit}
}

func (s *server) countListRows(ctx context.Context, from string, where sqlWhere) (int, error) {
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+from+` WHERE `+where.sql(), where.args...).Scan(&total)
	return total, err
}

// addTimeRange from（含）/ to（不含），RFC 3339，与诊断上报一致。
func addTimeRange(c *gin.Context, where *sqlWhere, column string) string {
	for _, bound := range []struct{ param, op string }{{"from", ">="}, {"to", "<"}} {
		raw := strings.TrimSpace(c.Query(bound.param))
		if raw == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return bound.param + " must be an RFC 3339 timestamp"
		}
		where.add(column+bound.op+"?", at.UTC())
	}
	return ""
}

// addEnumFilter 单值筛选，取值必须在白名单里。
func addEnumFilter(c *gin.Context, where *sqlWhere, param, column string, allowed ...string) string {
	value := strings.TrimSpace(c.Query(param))
	if value == "" {
		return ""
	}
	if !oneOf(value, allowed...) {
		return fmt.Sprintf("%s must be one of %s", param, strings.Join(allowed, ", "))
	}
	where.add(column+"=?", value)
	return ""
}

// addEnumListFilter 逗号分隔的多值筛选，每一项都必须在白名单里。
func addEnumListFilter(c *gin.Context, where *sqlWhere, param, column string, allowed ...string) string {
	raw := strings.TrimSpace(c.Query(param))
	if raw == "" {
		return ""
	}
	values := []any{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if !oneOf(item, allowed...) {
			return fmt.Sprintf("%s must be a comma-separated list of %s", param, strings.Join(allowed, ", "))
		}
		values = append(values, item)
	}
	where.add(column+" IN (?"+strings.Repeat(",?", len(values)-1)+")", values...)
	return ""
}

// addExactFilter 精确匹配；空值不加条件。
func addExactFilter(c *gin.Context, where *sqlWhere, param, column string) {
	if value := strings.TrimSpace(c.Query(param)); value != "" {
		where.add(column+"=?", value)
	}
}

// likePrefix 把输入当字面量做前缀匹配：% 和 _ 不能被当成通配符。
func likePrefix(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value) + "%"
}
