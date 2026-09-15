package config

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 配置文档会漂，而且漂了没人知道。
//
// 这个仓库已经吃过一次：生产示例里写着 `INDEXER_MYSQL_CONNECTION_LIMIT=4`，amos 上
// 也照着填了，而代码从来没读过这个键；开发示例缺了 BIND_ADDRESS、TRUSTED_PROXIES、
// ADMIN_API_ALLOWED_IPS 三个安全相关的键，本地照着配、到生产才第一次见到这些概念。
// 两边都是"改代码时没有同步改清单"，而没有任何东西会提醒。
//
// 所以这两条测试把代码当作唯一事实源，反过来检查文档和示例。加一个键而不写文档，
// `go test` 就红——这比任何"记得同步"的约定都可靠。
const (
	configurationDoc   = "../../docs/CONFIGURATION.md"
	productionExample  = "../../deploy/amos/rn-foundation.env.example"
	developmentExample = "../../.env.example"
)

// envKeysReadByCode 把 config.go 里真正读取的键名抠出来。
func envKeysReadByCode(t *testing.T) []string {
	t.Helper()
	// 扫**整个包**而不是只扫 config.go。备份那组键住在 backup.go 里，只读一个
	// 文件的话它们会从这道门禁底下整组溜过去——而它们恰恰是灾难当天要用的键。
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sources = append(sources, name)
	}
	sort.Strings(sources)

	// l.value("KEY", …) / l.integer / l.boolean / os.Getenv("KEY") / os.LookupEnv("KEY")
	pattern := regexp.MustCompile(`(?:l\.(?:value|integer|boolean)|os\.(?:Getenv|LookupEnv))\("([A-Z][A-Z0-9_]+)"`)
	seen := map[string]bool{}
	for _, name := range sources {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range pattern.FindAllStringSubmatch(string(source), -1) {
			seen[match[1]] = true
		}
	}
	// legacyMySQLKeys 是"已经不读了、但要认得出"的那一组，不属于可用键
	for _, key := range legacyMySQLKeys {
		delete(seen, key)
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) < 40 {
		t.Fatalf("只从 %v 里认出 %d 个键，正则多半失配了：%v", sources, len(keys), keys)
	}
	return keys
}

// 每个代码会读的键，配置参考里都要有一行。没有这一行，这个键对运维就不存在——
// 他只能靠读 Go 源码来回答"这台机器还能配什么"。
func TestEveryEnvKeyIsInTheConfigurationReference(t *testing.T) {
	doc, err := os.ReadFile(configurationDoc)
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, key := range envKeysReadByCode(t) {
		if !strings.Contains(string(doc), key) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("这些键代码会读，但 %s 里没有：\n  %s\n"+
			"加一个配置项要同时改三处：config 包、配置参考、两份 .env.example。",
			configurationDoc, strings.Join(missing, "\n  "))
	}
}

// 反过来：示例文件里出现的键必须是代码真的会读的。
//
// 挡的是 INDEXER_MYSQL_CONNECTION_LIMIT 那一类——看着像我们的、填了也不报错、
// 而代码从来没读过。配错了不报错的键，比配错了报错的键难查得多。
func TestExamplesDoNotOfferKeysNobodyReads(t *testing.T) {
	known := map[string]bool{}
	for _, key := range envKeysReadByCode(t) {
		known[key] = true
	}
	// 旧键在示例里只以"已经不再被读取"的说明形式出现，不是可设置项
	for _, key := range legacyMySQLKeys {
		known[key] = true
	}
	assignment := regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]+)=`)
	for _, path := range []string{productionExample, developmentExample} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var unknown []string
		for _, match := range assignment.FindAllStringSubmatch(string(raw), -1) {
			if !known[match[1]] {
				unknown = append(unknown, match[1])
			}
		}
		if len(unknown) > 0 {
			t.Errorf("%s 里这些键代码从不读取：%s", path, strings.Join(unknown, ", "))
		}
	}
}

// 值里含 shell 元字符却没加引号，是一条**机密泄漏路径**，不只是"加载不了"。
//
// 2026-09-13 的第二次泄漏就是这么来的：MYSQL_DSN 的值里有 tcp(...)，
// `set -a; . /etc/rn-foundation.env` 让 bash 报 syntax error，而 bash 报这个错时会
// 把出错那一整行**连口令一起**回显出来。
//
// systemd 的 EnvironmentFile 会剥掉引号（在 amos 上验过），所以加引号对两条加载
// 路径都成立，没有取舍。`deploy/amos/slim-env.py --check` 是同一条检查的线上版本。
func TestEnvExamplesAreSafeToSource(t *testing.T) {
	// 未加引号时会被 shell 解释的字符。空格和制表符也算：它们让赋值在中间断开。
	unsafe := "()&$`|;<>*?#'\" \t"
	for _, path := range []string{productionExample, developmentExample} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			key, value, found := strings.Cut(trimmed, "=")
			if !found {
				continue
			}
			if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
				continue // 已经加了引号
			}
			if strings.ContainsAny(value, unsafe) {
				t.Errorf("%s:%d %s 的值含 shell 元字符却没加引号。"+
					"source 这个文件时 bash 会报错并把整行连值一起回显——那是一条泄漏路径。",
					path, number+1, key)
			}
		}
	}
}
