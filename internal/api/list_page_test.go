package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func listTestContext(query string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/admin/list?"+query, nil)
	return c
}

// 倒序键集：下一页 = 排在游标那一行之后的所有行；每一列都要嵌套进去，否则同值的行会丢
func TestKeysetBeforeNestsEveryColumn(t *testing.T) {
	clause, args := keysetBefore([]string{"a", "b"}, []any{1, "x"})
	if clause != "(a<? OR (a=? AND b<?))" || fmt.Sprint(args) != "[1 1 x]" {
		t.Fatalf("two columns: %s %v", clause, args)
	}
	clause, args = keysetBefore([]string{"a", "b", "c"}, []any{1, 2, 3})
	if clause != "(a<? OR (a=? AND (b<? OR (b=? AND c<?))))" || fmt.Sprint(args) != "[1 1 2 2 3]" {
		t.Fatalf("three columns: %s %v", clause, args)
	}
}

// 游标往返：时间不丢精度；文本里带冒号也不会被拆错
func TestListCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 2, 3, 456_000_000, time.UTC)
	keys := []sortKey{{"created_at", cursorTime}, {"installation_id", cursorText}, {"id", cursorUint}}
	values, err := decodeListCursor(encodeListCursor(at, "inst:a:b", uint64(42)), keys)
	if err != nil {
		t.Fatal(err)
	}
	if !values[0].(time.Time).Equal(at) || values[1] != "inst:a:b" || values[2] != uint64(42) {
		t.Fatalf("round trip changed the values: %v", values)
	}
}

// 坏游标、越界 limit 都是客户端错误：报出来，不悄悄当成第一页
func TestParseListPageRejectsBadInput(t *testing.T) {
	keys := []sortKey{{"created_at", cursorTime}, {"id", cursorText}}
	for _, query := range []string{
		"limit=0", "limit=201", "limit=abc", "cursor=!!",
		"cursor=" + encodeListCursor("only-one"),
		"cursor=" + encodeListCursor("not-a-time", "id"),
		"cursor=" + encodeListCursor(time.Now(), ""),
	} {
		if _, invalid := parseListPage(listTestContext(query), keys...); invalid == "" {
			t.Fatalf("query %q must be rejected", query)
		}
	}
	page, invalid := parseListPage(listTestContext(""), keys...)
	if invalid != "" || page.limit != adminListDefaultLimit || len(page.after.clauses) != 0 {
		t.Fatalf("first page: %+v %q", page, invalid)
	}
	page, invalid = parseListPage(listTestContext("limit=200&cursor="+encodeListCursor(time.Now(), "aud_1")), keys...)
	if invalid != "" || page.limit != 200 || page.after.sql() != "(created_at<? OR (created_at=? AND id<?))" {
		t.Fatalf("cursor page: %+v %q", page, invalid)
	}
}

// 前缀匹配把输入当字面量：% 和 _ 不是通配符
func TestLikePrefixEscapesWildcards(t *testing.T) {
	if got := likePrefix(`1_2%\`); got != `1\_2\%\\%` {
		t.Fatalf("got %q", got)
	}
}

type listFilterParser func(*gin.Context) (sqlWhere, listPage, string)

var adminListParsers = map[string]listFilterParser{
	"audit":    func(c *gin.Context) (sqlWhere, listPage, string) { return parseAuditListFilter(c, "100000001") },
	"release":  func(c *gin.Context) (sqlWhere, listPage, string) { return parseReleaseListFilter(c, "100000001") },
	"ota":      func(c *gin.Context) (sqlWhere, listPage, string) { return parseOTAListFilter(c, "100000001") },
	"outbox":   func(c *gin.Context) (sqlWhere, listPage, string) { return parsePushOutboxFilter(c, "100000001") },
	"delivery": func(c *gin.Context) (sqlWhere, listPage, string) { return parsePushDeliveryFilter(c, "100000001") },
	"block":    parsePlatformBlockFilter,
	"transfer": parseScanTransferFilter,
}

// 非法筛选值一律拒绝：当成"不筛"会让运营以为筛过了
func TestAdminListFiltersRejectInvalidValues(t *testing.T) {
	for _, tc := range []struct{ parser, query string }{
		{"audit", "from=yesterday"},
		{"audit", "to=2026-09-14"},
		{"release", "platform=web"},
		{"release", "status=active,bogus"},
		{"ota", "status=completed"},
		{"ota", "platform=harmony"},
		{"outbox", "status=delivered"},
		{"delivery", "provider=sms"},
		{"delivery", "status=pending"},
		{"block", "status=all"},
		{"block", "address=0x12"},
		{"block", "limit=500"},
		{"transfer", "chain=nope&address=0x" + strings.Repeat("a", 40)},
		{"transfer", "chain=bsc&address=0x12"},
		{"transfer", "chain=bsc&address=0x" + strings.Repeat("a", 40) + "&direction=both"},
		{"transfer", "chain=bsc&address=0x" + strings.Repeat("a", 40) + "&status=pending"},
	} {
		if _, _, invalid := adminListParsers[tc.parser](listTestContext(tc.query)); invalid == "" {
			t.Fatalf("%s %q must be rejected", tc.parser, tc.query)
		}
	}
}

func TestAdminListFiltersBuildWhereClauses(t *testing.T) {
	for _, tc := range []struct {
		parser, query string
		fragments     []string
	}{
		{"audit", "action=publish&q=rel_1&from=2026-09-01T00:00:00Z", []string{"tenant_id=?", "action=?", "(target_id=? OR request_id=?)", "created_at>=?"}},
		{"release", "platform=android&status=verified,active&q=1.2", []string{"tenant_id=?", "platform=?", "status IN (?,?)", "version LIKE ?"}},
		{"ota", "platform=ios&status=active&channel=staging&baseReleaseId=rel_1", []string{"o.tenant_id=?", "o.platform=?", "o.status=?", "o.channel=?", "o.base_release_id=?"}},
		{"outbox", "status=failed&eventType=release_published&to=2026-09-14T00:00:00Z", []string{"o.tenant_id=?", "o.status=?", "o.event_type=?", "o.created_at<?"}},
		{"delivery", "status=failed&provider=fcm&installationId=inst_1&eventId=evt_1", []string{"d.tenant_id=?", "d.status=?", "d.provider=?", "d.installation_id=?", "d.event_id=?"}},
		{"block", "status=revoked", []string{"revoked_at IS NOT NULL"}},
		{"transfer", "chain=bsc&address=0x" + strings.Repeat("A", 40) + "&direction=out&status=orphaned", []string{"chain=?", "address_key=?", "direction=?", "status=?"}},
	} {
		where, _, invalid := adminListParsers[tc.parser](listTestContext(tc.query))
		if invalid != "" {
			t.Fatalf("%s %q rejected: %s", tc.parser, tc.query, invalid)
		}
		for _, fragment := range tc.fragments {
			if !strings.Contains(where.sql(), fragment) {
				t.Fatalf("%s where missing %s: %s", tc.parser, fragment, where.sql())
			}
		}
		if strings.Count(where.sql(), "?") != len(where.args) {
			t.Fatalf("%s placeholders and args disagree: %s %v", tc.parser, where.sql(), where.args)
		}
	}
}
