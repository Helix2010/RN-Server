package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 外部服务的接入配置，目前只有预测市场平台一段。
//
// 和钱包段一样存在 mobile-bootstrap 配置里、随 bootstrap 下发。它把本租户和预测平台
// 上的租户关联起来：两边的租户 id **不假定相同**（AGENTS.md「租户身份与外部系统的
// 对应」），关联只靠管理端填的接口域名 + 平台 scopeId + 我们这边的链。没有这条配置
// 就没有关联：predict 模块开着而配置缺失或不合法，写入时 400、下发时 503。

var (
	// 只接受裸主机名：协议、端口、路径都不是"域名"，App 按平台规则从它派生六个子域
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	// 平台的租户 scope：bytes32 的 0x-hex
	scopeIDPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
)

type predictService struct {
	Domain  string `json:"domain"`
	ScopeID string `json:"scopeId"`
	Chain   string `json:"chain"`
}

func (p predictService) asMap() map[string]any {
	return map[string]any{"domain": p.Domain, "scopeId": p.ScopeID, "chain": p.Chain}
}

func predictNetwork(id string) *evmNetwork {
	for i := range supportedNetworks {
		if supportedNetworks[i].ID == id {
			return &supportedNetworks[i]
		}
	}
	return nil
}

// parsePredictService 校验并归一化一条预测平台配置（域名与 scopeId 转小写）。
func parsePredictService(raw any) (predictService, error) {
	item := object(raw)
	if item == nil {
		return predictService{}, errors.New("services.predict must be an object")
	}
	domain := strings.ToLower(strings.TrimSpace(text(item["domain"], "")))
	if !hostnamePattern.MatchString(domain) {
		return predictService{}, errors.New("services.predict.domain must be a bare hostname such as predict.example.com (no protocol, port or path)")
	}
	scopeID := strings.ToLower(strings.TrimSpace(text(item["scopeId"], "")))
	if !scopeIDPattern.MatchString(scopeID) {
		return predictService{}, errors.New("services.predict.scopeId must be 0x followed by 64 hex characters")
	}
	chain := strings.TrimSpace(text(item["chain"], ""))
	if predictNetwork(chain) == nil {
		return predictService{}, fmt.Errorf("services.predict.chain %q is not in the platform chain catalog", chain)
	}
	return predictService{Domain: domain, ScopeID: scopeID, Chain: chain}, nil
}

// parseServicesSection 校验管理端写入的 services 段。只认识 predict；不认识的键拒绝，
// 拼错的键不能静默落库。
func parseServicesSection(raw any) (map[string]any, error) {
	section := object(raw)
	if section == nil {
		return nil, errors.New("services must be an object")
	}
	out := map[string]any{}
	for key, value := range section {
		switch key {
		case "predict":
			if value == nil {
				continue
			}
			predict, err := parsePredictService(value)
			if err != nil {
				return nil, err
			}
			out["predict"] = predict.asMap()
		default:
			return nil, fmt.Errorf("services.%s is not a known service", key)
		}
	}
	return out, nil
}

// storedServicesSection 取库里已有的 services 段：PATCH 不带这一段时沿用，同 wallet。
func storedServicesSection(stored []byte) map[string]any {
	var current map[string]any
	if len(stored) == 0 || json.Unmarshal(stored, &current) != nil {
		return nil
	}
	if section, ok := current["services"].(map[string]any); ok {
		return section
	}
	return nil
}

// normalizeServices 是读路径的归一化。写入时已经校验过，库里出现不合法条目就是事故：
// 不下发、留 warning，不修不补。返回值永远是对象。
func normalizeServices(raw any) map[string]any {
	out := map[string]any{}
	section := object(raw)
	if section == nil {
		return out
	}
	if value, ok := section["predict"]; ok && value != nil {
		predict, err := parsePredictService(value)
		if err != nil {
			slog.Warn("stored services.predict is invalid and will not be delivered", "error", err)
			return out
		}
		out["predict"] = predict.asMap()
	}
	return out
}

// predictServiceFor 决定下发什么：predict 模块开着就必须有完整合法的配置，且链在租户
// 启用的链集合里，否则返回错误（写入 400 / 下发 503）；关着返回 nil。
func predictServiceFor(modules, services, wallet map[string]any) (*predictService, error) {
	if !truth(modules["predict"]) {
		return nil, nil
	}
	raw, ok := services["predict"]
	if !ok || raw == nil {
		return nil, errors.New("the Predict module is enabled but services.predict is not configured")
	}
	predict, err := parsePredictService(raw)
	if err != nil {
		return nil, err
	}
	chains, _ := wallet["chains"].([]any)
	for _, chain := range chains {
		if chain == predict.Chain {
			return &predict, nil
		}
	}
	return nil, fmt.Errorf("services.predict.chain %q is not among the tenant's enabled chains", predict.Chain)
}

// gammaPublicInfoURL 按平台规则派生 public-info 地址；测试替换它指向本地服务。
var gammaPublicInfoURL = func(domain string) string {
	return "https://gamma-api." + domain + "/public-info"
}

var predictProbeHTTP = &http.Client{Timeout: 10 * time.Second}

// probePredictService 是管理端「测试连接」：拿所填的域名去请求平台的 public-info，
// 把平台返回的 scopeId 与链和所填的比对。配错成别的租户的平台，在保存前就能发现——
// 这两个字段决定用户凭证发往哪里。
func (s *server) probePredictService(c *gin.Context) {
	var body struct {
		Domain  string `json:"domain"`
		ScopeID string `json:"scopeId"`
		Chain   string `json:"chain"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_SERVICES_CONFIG", "domain, scopeId and chain are required")
		return
	}
	predict, err := parsePredictService(map[string]any{"domain": body.Domain, "scopeId": body.ScopeID, "chain": body.Chain})
	if err != nil {
		problem(c, 400, "INVALID_SERVICES_CONFIG", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, gammaPublicInfoURL(predict.Domain), nil)
	if err != nil {
		problem(c, 400, "INVALID_SERVICES_CONFIG", "domain cannot be turned into a request")
		return
	}
	request.Header.Set("X-Tenant-Domain", predict.Domain)
	request.Header.Set("Accept", "application/json")
	response, err := predictProbeHTTP.Do(request)
	if err != nil {
		problem(c, 502, "PREDICT_PROBE_FAILED", "gamma-api."+predict.Domain+" is unreachable: "+err.Error())
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		problem(c, 502, "PREDICT_PROBE_FAILED", fmt.Sprintf("gamma-api.%s answered HTTP %d for /public-info", predict.Domain, response.StatusCode))
		return
	}
	var info struct {
		ScopeID string `json:"scopeId"`
		Chain   struct {
			ChainID int    `json:"chainId"`
			Name    string `json:"name"`
		} `json:"chain"`
		Brand struct {
			Title string `json:"title"`
		} `json:"brand"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&info); err != nil {
		problem(c, 502, "PREDICT_PROBE_FAILED", "public-info is not valid JSON")
		return
	}
	problems := []string{}
	if strings.ToLower(strings.TrimSpace(info.ScopeID)) != predict.ScopeID {
		problems = append(problems, fmt.Sprintf("平台返回的 scopeId（%s）与所填不一致", info.ScopeID))
	}
	network := predictNetwork(predict.Chain)
	if info.Chain.ChainID != network.ChainID {
		problems = append(problems, fmt.Sprintf("平台的链是 %s（chainId %d），所选链 %s 的 chainId 是 %d", info.Chain.Name, info.Chain.ChainID, network.Name, network.ChainID))
	}
	c.JSON(200, gin.H{
		"ok":        len(problems) == 0,
		"brand":     info.Brand.Title,
		"chainId":   info.Chain.ChainID,
		"chainName": info.Chain.Name,
		"scopeId":   info.ScopeID,
		"problems":  problems,
	})
}
