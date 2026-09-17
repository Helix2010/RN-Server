package api

import (
	"fmt"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// 管理端列表分页的库测（设计 admin-list-pagination-2026-09-14 §6）：每个列表造超过一页的
// 数据，用 limit=2 翻完，断言顺序对、不重不漏、total 是筛选之后的真实计数。

// pageThrough 按 limit=2 把列表翻完，返回每行的标识（按返回顺序）与第一页的 total（没有 total 为 -1）。
func pageThrough(t *testing.T, call func(query string) *httptest.ResponseRecorder, filter string, key func(map[string]any) string) ([]string, int) {
	t.Helper()
	keys, total, cursor := []string{}, -1, ""
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatalf("pagination with %q did not terminate", filter)
		}
		query := filter + "&limit=2"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		recorder := call(query)
		if recorder.Code != 200 {
			t.Fatalf("%s: %d %s", query, recorder.Code, recorder.Body.String())
		}
		body := decodeBody(t, recorder)
		if pages == 0 {
			if value, ok := body["total"].(float64); ok {
				total = int(value)
			}
		}
		items, _ := body["items"].([]any)
		if len(items) > 2 {
			t.Fatalf("page larger than the limit: %d", len(items))
		}
		for _, item := range items {
			keys = append(keys, key(item.(map[string]any)))
		}
		next, _ := body["nextCursor"].(string)
		if hasMore, _ := body["hasMore"].(bool); hasMore != (next != "") {
			t.Fatalf("hasMore=%v disagrees with nextCursor=%q", hasMore, next)
		}
		if next == "" {
			return keys, total
		}
		cursor = next
	}
}

func listField(names ...string) func(map[string]any) string {
	return func(item map[string]any) string {
		key := ""
		for i, name := range names {
			if i > 0 {
				key += "|"
			}
			if number, ok := item[name].(float64); ok {
				key += strconv.FormatFloat(number, 'f', -1, 64)
				continue
			}
			key += fmt.Sprint(item[name])
		}
		return key
	}
}

func assertListKeys(t *testing.T, label string, got []string, total int, want []string, wantTotal int) {
	t.Helper()
	if len(want) == 0 {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
	if total != wantTotal {
		t.Fatalf("%s: total %d, want %d", label, total, wantTotal)
	}
}

func TestDBAuditEventsPageInOrderAndFilter(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(21)
	suffix := uniqueSuffix()
	base := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	// 第 1、2 条是同一毫秒：只能靠 id 决胜，翻页时既不能丢也不能重复
	seeds := []struct {
		offset         time.Duration
		action, target string
	}{
		{0, "publish", "rel_a"}, {time.Second, "publish", "rel_b"}, {time.Second, "pause", "rel_b"},
		{2 * time.Second, "publish", "rel_c"}, {3 * time.Second, "pause", "rel_c"},
	}
	ids := make([]string, len(seeds))
	for i, seed := range seeds {
		ids[i] = fmt.Sprintf("aud_%s_%d", suffix, i)
		if _, err := db.Exec(`INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?,'{}',?)`,
			ids[i], tenant, "ops@example.com", seed.action, "release", seed.target, "list test", "req_"+ids[i], base.Add(seed.offset)); err != nil {
			t.Fatalf("insert audit: %v", err)
		}
	}
	call := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "GET", "/v1/admin/audit-events?"+query, nil)
		s.listAudits(c)
		return recorder
	}
	id := listField("id")
	keys, total := pageThrough(t, call, "", id)
	assertListKeys(t, "all", keys, total, []string{ids[4], ids[3], ids[2], ids[1], ids[0]}, 5)
	keys, total = pageThrough(t, call, "action=publish", id)
	assertListKeys(t, "action", keys, total, []string{ids[3], ids[1], ids[0]}, 3)
	keys, total = pageThrough(t, call, "q=rel_b", id)
	assertListKeys(t, "target", keys, total, []string{ids[2], ids[1]}, 2)
	keys, total = pageThrough(t, call, "q=req_"+ids[3], id)
	assertListKeys(t, "request id", keys, total, []string{ids[3]}, 1)
	keys, total = pageThrough(t, call, "from="+base.Add(time.Second).Format(time.RFC3339)+"&to="+base.Add(3*time.Second).Format(time.RFC3339), id)
	assertListKeys(t, "time range", keys, total, []string{ids[3], ids[2], ids[1]}, 3)
}

func TestDBReleaseListPagesByBuildNumberAndFilters(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(22)
	suffix := uniqueSuffix()
	now := time.Now().UTC()
	id := func(key string) string { return "rel_" + suffix + "_" + key }
	for _, seed := range []struct {
		key, platform, version string
		build                  int
		status                 string
	}{
		{"a1", "android", "1.0.1", 1, "completed"},
		{"a2", "android", "1.2.0", 2, "paused"},
		{"i2", "ios", "1.2.0", 2, "verified"},
		{"a3", "android", "1.3.0", 3, "active"},
		{"a4", "android", "1.3.1", 4, "canary"},
	} {
		if _, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,file_metadata,file_name,content_type,object_key,expected_size,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'{}','{}','app.apk','application/vnd.android.package-archive',?,10,'tester',?,?)`,
			id(seed.key), tenant, seed.platform, seed.version, seed.build, "runtime-"+seed.version, seed.status, "tenants/"+tenant+"/"+seed.key, now, now); err != nil {
			t.Fatalf("insert release: %v", err)
		}
	}
	call := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "GET", "/v1/admin/releases?"+query, nil)
		s.listReleases(c)
		return recorder
	}
	key := listField("id")
	// 同一个 build 号跨平台由 id 决胜：i2 排在 a2 前面
	keys, total := pageThrough(t, call, "", key)
	assertListKeys(t, "all", keys, total, []string{id("a4"), id("a3"), id("i2"), id("a2"), id("a1")}, 5)
	keys, total = pageThrough(t, call, "platform=android", key)
	assertListKeys(t, "platform", keys, total, []string{id("a4"), id("a3"), id("a2"), id("a1")}, 4)
	keys, total = pageThrough(t, call, "status=verified,active,completed", key)
	assertListKeys(t, "statuses", keys, total, []string{id("a3"), id("i2"), id("a1")}, 3)
	keys, total = pageThrough(t, call, "q=1.3", key)
	assertListKeys(t, "version prefix", keys, total, []string{id("a4"), id("a3")}, 2)
	keys, total = pageThrough(t, call, "q=1_3", key)
	assertListKeys(t, "underscore is literal", keys, total, nil, 0)
	if recorder := call("status=bogus"); recorder.Code != 422 {
		t.Fatalf("bogus status: %d", recorder.Code)
	}
}

func TestDBOTAListPagesAndOffersEveryBaseAsAFilter(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(23)
	suffix := uniqueSuffix()
	now := time.Now().UTC().Truncate(time.Millisecond)
	baseID := func(key string) string { return "rel_" + suffix + "_" + key }
	// 已暂停的基线也要出现在筛选项里：/ota/base-releases 只列 verified/active
	for i, base := range []struct{ key, status string }{{"old", "paused"}, {"new", "active"}} {
		if _, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,file_metadata,file_name,content_type,object_key,expected_size,created_by,created_at,updated_at) VALUES(?,?,'android',?,?,'4.0.0',?,'{}','{}','app.apk','application/vnd.android.package-archive',?,10,'tester',?,?)`,
			baseID(base.key), tenant, fmt.Sprintf("1.%d.0", i), i+1, base.status, "tenants/"+tenant+"/"+base.key, now, now); err != nil {
			t.Fatalf("insert base release: %v", err)
		}
	}
	otaID := func(key string) string { return "ota_" + suffix + "_" + key }
	for _, seed := range []struct {
		key, base, channel, status string
		revision                   int
		offset                     time.Duration
	}{
		{"p1", "old", "production", "superseded", 1, 0},
		{"p2", "old", "production", "active", 2, time.Second},
		{"s1", "new", "staging", "verified", 1, 2 * time.Second},
		{"p3", "new", "production", "active", 3, 3 * time.Second},
	} {
		created := now.Add(seed.offset)
		if _, err := db.Exec(`INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,release_kind,status,release_notes,created_by,created_at,updated_at) VALUES(?,?,?,'android',?,'4.0.0',?,?,'update',?,'{}','tester',?,?)`,
			otaID(seed.key), tenant, baseID(seed.base), seed.channel, seed.revision, "upd-"+suffix+"-"+seed.key, seed.status, created, created); err != nil {
			t.Fatalf("insert ota: %v", err)
		}
	}
	call := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "GET", "/v1/admin/ota/releases?"+query, nil)
		s.listOTAReleases(c)
		return recorder
	}
	key := listField("id")
	// 按发布时间倒序，不按 revision：s1 是 staging 的第 1 版、p2 是 production 的第 2 版，
	// revision 跨分组没有可比性，s1 比 p2 晚发就排在它前面
	keys, total := pageThrough(t, call, "", key)
	assertListKeys(t, "all", keys, total, []string{otaID("p3"), otaID("s1"), otaID("p2"), otaID("p1")}, 4)
	keys, total = pageThrough(t, call, "baseReleaseId="+baseID("old"), key)
	assertListKeys(t, "base", keys, total, []string{otaID("p2"), otaID("p1")}, 2)
	keys, total = pageThrough(t, call, "channel=staging", key)
	assertListKeys(t, "channel", keys, total, []string{otaID("s1")}, 1)
	keys, total = pageThrough(t, call, "status=active", key)
	assertListKeys(t, "status", keys, total, []string{otaID("p3"), otaID("p2")}, 2)

	recorder := call("limit=1")
	bases, _ := decodeBody(t, recorder)["baseReleases"].([]any)
	got := []string{}
	for _, base := range bases {
		got = append(got, listField("id")(base.(map[string]any)))
	}
	if !reflect.DeepEqual(got, []string{baseID("new"), baseID("old")}) {
		t.Fatalf("baseReleases must list every base that has OTA records, newest build first: %v", got)
	}
	if recorder := call("status=completed"); recorder.Code != 422 {
		t.Fatalf("completed is not an OTA status: %d", recorder.Code)
	}
}

func TestDBPushListsPageAndCountWithinFilters(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(24)
	suffix := uniqueSuffix()
	now := time.Now().UTC().Truncate(time.Millisecond)
	event := func(i int) string { return fmt.Sprintf("evt_%s_%d", suffix, i) }
	for i, seed := range []struct{ eventType, status string }{
		{"release_published", "sent"}, {"release_published", "partial_failed"}, {"release_paused", "failed"},
	} {
		created := now.Add(time.Duration(i) * time.Second)
		if _, err := db.Exec(`INSERT INTO app_push_outbox(id,tenant_id,event_type,payload,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,'{}',?,1,?,?,?)`,
			event(i), tenant, seed.eventType, seed.status, created, created, created); err != nil {
			t.Fatalf("insert outbox: %v", err)
		}
	}
	installation := func(name string) string { return "inst_" + suffix + "_" + name }
	// 四条投递同一时刻：只能靠主键三列决胜
	for _, seed := range []struct {
		event                  int
		name, provider, status string
	}{
		{0, "a", "fcm", "sent"}, {0, "b", "fcm", "sent"}, {0, "b", "apns", "failed"}, {1, "a", "hms", "failed"},
	} {
		if _, err := db.Exec(`INSERT INTO app_push_deliveries(event_id,tenant_id,installation_id,provider,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			event(seed.event), tenant, installation(seed.name), seed.provider, seed.status, now, now); err != nil {
			t.Fatalf("insert delivery: %v", err)
		}
	}
	outbox := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "GET", "/v1/admin/push/outbox?"+query, nil)
		s.listPushOutbox(c)
		return recorder
	}
	keys, total := pageThrough(t, outbox, "", listField("id"))
	assertListKeys(t, "outbox", keys, total, []string{event(2), event(1), event(0)}, 3)
	keys, total = pageThrough(t, outbox, "status=failed", listField("id"))
	assertListKeys(t, "outbox status", keys, total, []string{event(2)}, 1)
	keys, total = pageThrough(t, outbox, "eventType=release_published", listField("id"))
	assertListKeys(t, "outbox event type", keys, total, []string{event(1), event(0)}, 2)

	deliveries := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "GET", "/v1/admin/push/deliveries?"+query, nil)
		s.listPushDeliveries(c)
		return recorder
	}
	key := listField("eventId", "installationId", "provider")
	row := func(i int, name, provider string) string { return event(i) + "|" + installation(name) + "|" + provider }
	keys, total = pageThrough(t, deliveries, "", key)
	assertListKeys(t, "deliveries", keys, total, []string{row(1, "a", "hms"), row(0, "b", "fcm"), row(0, "b", "apns"), row(0, "a", "fcm")}, 4)
	keys, total = pageThrough(t, deliveries, "status=failed", key)
	assertListKeys(t, "delivery status", keys, total, []string{row(1, "a", "hms"), row(0, "b", "apns")}, 2)
	keys, total = pageThrough(t, deliveries, "provider=fcm", key)
	assertListKeys(t, "delivery provider", keys, total, []string{row(0, "b", "fcm"), row(0, "a", "fcm")}, 2)
	keys, total = pageThrough(t, deliveries, "installationId="+installation("a"), key)
	assertListKeys(t, "delivery installation", keys, total, []string{row(1, "a", "hms"), row(0, "a", "fcm")}, 2)
}

func TestDBPlatformBlockListPagesAndFiltersByStatus(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	// 平台级表跨测试共享：用本次运行专属的地址把数据圈出来
	address, addressKey, ok := normalizeWalletAddress("0x" + testHex(40))
	if !ok {
		t.Fatal("generated address was rejected")
	}
	base := time.Now().UTC().Truncate(time.Millisecond)
	ids := []string{}
	for i, revoked := range []bool{true, true, false} {
		created := base.Add(time.Duration(i) * time.Second)
		var revokedAt, revokedBy, revokedReason any
		if revoked {
			revokedAt, revokedBy, revokedReason = created.Add(time.Minute), "ops", "cleared"
		}
		result, err := db.Exec(`INSERT INTO platform_wallet_block(address_key,address,reason,created_by,created_at,revoked_at,revoked_by,revoked_reason) VALUES(?,?,?,?,?,?,?,?)`,
			addressKey, address, "list test", "ops", created, revokedAt, revokedBy, revokedReason)
		if err != nil {
			t.Fatalf("insert block: %v", err)
		}
		id, _ := result.LastInsertId()
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	call := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, "", "GET", "/v1/admin/platform/wallet/blocks?"+query, nil)
		s.listPlatformWalletBlocks(c)
		return recorder
	}
	key := listField("id")
	keys, total := pageThrough(t, call, "address="+address, key)
	assertListKeys(t, "all", keys, total, []string{ids[2], ids[1], ids[0]}, 3)
	keys, total = pageThrough(t, call, "address="+address+"&status=active", key)
	assertListKeys(t, "active", keys, total, []string{ids[2]}, 1)
	keys, total = pageThrough(t, call, "address="+address+"&status=revoked", key)
	assertListKeys(t, "revoked", keys, total, []string{ids[1], ids[0]}, 2)
	if recorder := call("status=all"); recorder.Code != 422 {
		t.Fatalf("status=all must be rejected: %d", recorder.Code)
	}
}

func TestDBScanTransfersPageByBlockWithoutTotal(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(25)
	// 跨租户查询：用本次运行专属的地址把数据圈出来
	address := "0x" + testHex(40)
	base := time.Now().UTC().Truncate(time.Millisecond)
	// 两条同一区块：只能靠 id 决胜
	seeds := []struct {
		block     uint64
		direction string
		status    string
	}{
		{10, "in", "confirmed"}, {11, "out", "confirmed"}, {11, "in", "orphaned"}, {12, "out", "confirmed"}, {13, "in", "confirmed"},
	}
	ids := make([]string, len(seeds))
	for i, seed := range seeds {
		result, err := db.Exec(`INSERT INTO wallet_transfer_index(tenant_id,chain,address_key,direction,asset,contract_address,amount_raw,counterparty,tx_hash,log_index,block_number,block_hash,block_time,attribution,status,created_at) VALUES(?,'bsc',?,?,'native','native',1,'',?,?,?,?,?,'tx',?,?)`,
			tenant, address, seed.direction, "0x"+testHex(64), i, seed.block, "0x"+testHex(64), base, seed.status, base)
		if err != nil {
			t.Fatalf("insert transfer: %v", err)
		}
		id, _ := result.LastInsertId()
		ids[i] = strconv.FormatInt(id, 10)
	}
	call := func(query string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, "", "GET", "/v1/admin/platform/scan/transfers?chain=bsc&address="+address+"&"+query, nil)
		s.scanTransfers(c)
		return recorder
	}
	key := func(item map[string]any) string {
		return fmt.Sprintf("%v/%v", item["blockNumber"], item["direction"])
	}
	keys, total := pageThrough(t, call, "", key)
	// 同是 11 号块：后插入的 id 更大，排在前面
	assertListKeys(t, "all", keys, total, []string{"13/in", "12/out", "11/in", "11/out", "10/in"}, -1)
	keys, total = pageThrough(t, call, "direction=out", key)
	assertListKeys(t, "direction", keys, total, []string{"12/out", "11/out"}, -1)
	keys, total = pageThrough(t, call, "status=orphaned", key)
	assertListKeys(t, "status", keys, total, []string{"11/in"}, -1)
	if recorder := call("direction=both"); recorder.Code != 400 {
		t.Fatalf("direction=both must be rejected: %d", recorder.Code)
	}
	_ = ids
}
