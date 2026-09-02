// Package chain 从平台自己的节点读取 ERC-20 代币的 symbol / name / decimals。
//
// 这一步是把外部数据写进数据库，而节点不可信：租户能配的 RPC 可以返回假
// decimals，公共节点也可能指错链或返回巨大响应。所以这里只接受调用方给的平台
// 默认端点，先核对 eth_chainId，再确认地址上有代码，每次调用限时限量，解出来的
// 字符串还要过一遍清洗。任何一步不满足都拒绝，宁可让运营多试一次，也不能把错的
// 精度写进库——decimals 错一位金额就差 10 倍。
package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// CallTimeout 是单次 JSON-RPC 调用的上限。
	CallTimeout = 5 * time.Second
	// MaxResponseBytes 是单次响应体的上限；symbol/name/decimals 的合法返回远小于此。
	MaxResponseBytes = 64 << 10
	// MaxSymbolLength / MaxNameLength 与数据库列宽一致。
	MaxSymbolLength = 32
	MaxNameLength   = 128
	// MaxDecimals 之上的精度没有真实代币会用，多半是坏合约或恶意返回。
	MaxDecimals = 36

	selectorSymbol   = "0x95d89b41"
	selectorName     = "0x06fdde03"
	selectorDecimals = "0x313ce567"
)

// Kind 是读取失败的分类，调用方据此映射到对外的错误码。
type Kind int

const (
	// KindUnavailable：节点不可达、超时、HTTP 非 200、响应不是合法 JSON-RPC 或超过大小上限。
	KindUnavailable Kind = iota
	// KindChainMismatch：端点的 eth_chainId 与目录不符。
	KindChainMismatch
	// KindNotAContract：地址上没有代码。
	KindNotAContract
	// KindMetadataInvalid：symbol / name / decimals 缺失、无法解码或不合法。
	KindMetadataInvalid
)

func (k Kind) String() string {
	switch k {
	case KindChainMismatch:
		return "chain mismatch"
	case KindNotAContract:
		return "not a contract"
	case KindMetadataInvalid:
		return "metadata invalid"
	default:
		return "chain unavailable"
	}
}

// Error 带分类的读取错误。
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Kind.String() + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Err: fmt.Errorf(format, args...)}
}

// Network 是要读取的链：目录里的 chainId 与平台默认端点。
type Network struct {
	ID        string
	ChainID   int
	Endpoints []string
}

// Metadata 是链上读到并清洗过的代币元数据。
type Metadata struct {
	Symbol   string
	Name     string
	Decimals int
}

// Reader 通过 JSON-RPC over HTTP 读取代币元数据。
type Reader struct {
	client *http.Client
	// CallTimeout 可在测试里调短；生产用默认的 CallTimeout。
	CallTimeout time.Duration
}

// NewReader 构造读取器；client 为 nil 时用默认 http.Client。
func NewReader(client *http.Client) *Reader {
	if client == nil {
		client = &http.Client{}
	}
	return &Reader{client: client, CallTimeout: CallTimeout}
}

// ReadToken 依次尝试网络的每个端点。只有"节点不可用"才换下一个端点：链不符、
// 不是合约、元数据不合法都是确定性的结论，换端点不会变。
func (r *Reader) ReadToken(ctx context.Context, network Network, address string) (Metadata, error) {
	if len(network.Endpoints) == 0 {
		return Metadata{}, fail(KindUnavailable, "network %s has no platform endpoint", network.ID)
	}
	var lastErr error
	for _, endpoint := range network.Endpoints {
		meta, err := r.readFrom(ctx, endpoint, network.ChainID, address)
		if err == nil {
			return meta, nil
		}
		if KindOf(err) != KindUnavailable {
			return Metadata{}, err
		}
		lastErr = err
	}
	return Metadata{}, lastErr
}

func (r *Reader) readFrom(ctx context.Context, endpoint string, chainID int, address string) (Metadata, error) {
	// 1. 先核对链：端点指错链时，后面读到的全是别的链上同地址合约的数据
	rawChainID, err := r.call(ctx, endpoint, "eth_chainId", nil)
	if err != nil {
		return Metadata{}, unavailable(err)
	}
	gotChainID, err := hexQuantity(rawChainID)
	if err != nil {
		return Metadata{}, fail(KindUnavailable, "eth_chainId: %v", err)
	}
	if gotChainID.Cmp(big.NewInt(int64(chainID))) != 0 {
		return Metadata{}, fail(KindChainMismatch, "endpoint reports chain %s, catalog says %d", gotChainID, chainID)
	}
	// 2. 地址上必须有代码：转给普通地址的代币会永久丢失
	rawCode, err := r.call(ctx, endpoint, "eth_getCode", []any{address, "latest"})
	if err != nil {
		return Metadata{}, unavailable(err)
	}
	code, err := hexBytes(rawCode)
	if err != nil {
		return Metadata{}, fail(KindUnavailable, "eth_getCode: %v", err)
	}
	if len(code) == 0 {
		return Metadata{}, fail(KindNotAContract, "no code at %s", address)
	}
	// 3. symbol 与 decimals 必须读到；name 允许缺失（老合约不一定实现），缺了由运营补
	symbolData, err := r.ethCall(ctx, endpoint, address, selectorSymbol)
	if err != nil {
		return Metadata{}, err
	}
	symbol, err := decodeText(symbolData)
	if err != nil {
		return Metadata{}, fail(KindMetadataInvalid, "symbol(): %v", err)
	}
	symbol, err = SanitizeText(symbol, MaxSymbolLength)
	if err != nil || symbol == "" {
		return Metadata{}, fail(KindMetadataInvalid, "symbol(): %v", orEmpty(err))
	}
	decimalsData, err := r.ethCall(ctx, endpoint, address, selectorDecimals)
	if err != nil {
		return Metadata{}, err
	}
	decimals, err := decodeDecimals(decimalsData)
	if err != nil {
		return Metadata{}, fail(KindMetadataInvalid, "decimals(): %v", err)
	}
	name := ""
	nameData, nameErr := r.ethCall(ctx, endpoint, address, selectorName)
	if nameErr != nil {
		if KindOf(nameErr) == KindUnavailable {
			return Metadata{}, nameErr
		}
		// revert 之类：老合约可以没有 name()，留空由运营在表单里补
	} else if decoded, decodeErr := decodeText(nameData); decodeErr == nil {
		// name 只是预填、可人工修订：带 emoji 或超长就留空让运营补，
		// 不能因为它拒掉整个代币——symbol / decimals 才是必须干净的
		if cleaned, sanitizeErr := SanitizeText(decoded, MaxNameLength); sanitizeErr == nil {
			name = cleaned
		}
	}
	return Metadata{Symbol: symbol, Name: name, Decimals: decimals}, nil
}

// KindOf 取错误的分类；不是本包的错误一律视为节点不可用。
func KindOf(err error) Kind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return KindUnavailable
}

func orEmpty(err error) error {
	if err == nil {
		return errors.New("empty after trimming")
	}
	return err
}

// ethCall 读一个无参 view 函数的返回值。JSON-RPC 层面的错误（多半是 revert）说明
// 合约不按 ERC-20 回答，归为元数据不合法；传输层错误才是节点不可用。
func (r *Reader) ethCall(ctx context.Context, endpoint, address, selector string) ([]byte, error) {
	raw, err := r.call(ctx, endpoint, "eth_call", []any{map[string]string{"to": address, "data": selector}, "latest"})
	if err != nil {
		var rpcErr *rpcError
		if errors.As(err, &rpcErr) {
			return nil, fail(KindMetadataInvalid, "eth_call %s rejected by node (code %d)", selector, rpcErr.Code)
		}
		return nil, unavailable(err)
	}
	data, err := hexBytes(raw)
	if err != nil {
		return nil, fail(KindMetadataInvalid, "eth_call %s: %v", selector, err)
	}
	return data, nil
}

func unavailable(err error) error {
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	return &Error{Kind: KindUnavailable, Err: err}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message)
}

// call 发一次 JSON-RPC 请求。超时与响应体上限都在这里兜底，调用方不必各自记得。
func (r *Reader) call(ctx context.Context, endpoint, method string, params []any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	callCtx, cancel := context.WithTimeout(ctx, r.CallTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", method, response.StatusCode)
	}
	// 多读一个字节就能区分"正好 64KB"和"超过 64KB"
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxResponseBytes {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", method, MaxResponseBytes)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%s: malformed json-rpc response", method)
	}
	if envelope.Error != nil {
		return nil, envelope.Error
	}
	if len(envelope.Result) == 0 {
		return nil, fmt.Errorf("%s: response has no result", method)
	}
	return envelope.Result, nil
}

// hexBytes 把 JSON 里的 "0x…" 字符串解成字节；"0x" 解成空切片。
func hexBytes(raw json.RawMessage) ([]byte, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("result is not a string")
	}
	if !strings.HasPrefix(value, "0x") {
		return nil, errors.New("result is not 0x-prefixed hex")
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, errors.New("result is not valid hex")
	}
	return decoded, nil
}

// hexQuantity 解 JSON-RPC 的数量型返回（eth_chainId 这类不定长、无前导零的十六进制）。
func hexQuantity(raw json.RawMessage) (*big.Int, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("result is not a string")
	}
	if !strings.HasPrefix(value, "0x") || len(value) == 2 {
		return nil, errors.New("result is not a hex quantity")
	}
	number, ok := new(big.Int).SetString(value[2:], 16)
	if !ok {
		return nil, errors.New("result is not a hex quantity")
	}
	return number, nil
}

// decodeText 解 symbol() / name() 的返回。规范代币返回 ABI string（偏移 + 长度 +
// 内容），MKR 这类老合约返回 bytes32。按长度分支：正好 32 字节且不是一个悬空的
// ABI 动态头就是 bytes32，其余按 ABI string 解，解不动就拒绝。
func decodeText(data []byte) (string, error) {
	switch {
	case len(data) == 0:
		return "", errors.New("empty return data")
	case len(data) == 32:
		if isDanglingHead(data) {
			return "", errors.New("truncated ABI string")
		}
		text := bytes.TrimRight(data, "\x00")
		if !utf8.Valid(text) {
			return "", errors.New("bytes32 is not valid UTF-8")
		}
		return string(text), nil
	case len(data) >= 64:
		offset, ok := wordToInt(data[:32])
		if !ok || offset+32 > len(data) {
			return "", errors.New("ABI string offset out of range")
		}
		length, ok := wordToInt(data[offset : offset+32])
		if !ok || offset+32+length > len(data) {
			return "", errors.New("ABI string length out of range")
		}
		text := data[offset+32 : offset+32+length]
		if !utf8.Valid(text) {
			return "", errors.New("ABI string is not valid UTF-8")
		}
		return string(text), nil
	default:
		return "", fmt.Errorf("unexpected return length %d", len(data))
	}
}

// isDanglingHead 识别"只有偏移词、没有内容"的 32 字节返回：那是被截断的 ABI
// string，不是 bytes32。
func isDanglingHead(word []byte) bool {
	for _, b := range word[:31] {
		if b != 0 {
			return false
		}
	}
	return word[31] == 0x20
}

// wordToInt 把一个 32 字节的 uint256 转成 int，超出 int 范围视为无效。
func wordToInt(word []byte) (int, bool) {
	value := new(big.Int).SetBytes(word)
	if !value.IsInt64() || value.Int64() > int64(MaxResponseBytes) {
		return 0, false
	}
	return int(value.Int64()), true
}

// decodeDecimals 解 decimals()：必须正好一个 uint256 词，且在 0～MaxDecimals 内。
func decodeDecimals(data []byte) (int, error) {
	if len(data) != 32 {
		return 0, fmt.Errorf("unexpected return length %d", len(data))
	}
	value := new(big.Int).SetBytes(data)
	if !value.IsInt64() || value.Int64() > MaxDecimals {
		return 0, fmt.Errorf("decimals %s is outside 0..%d", value, MaxDecimals)
	}
	return int(value.Int64()), nil
}

// SanitizeText 清洗链上读到（或运营填写）的文本：去首尾空白，只允许可打印 ASCII
// 与 Unicode 字母数字，长度不超过 limit。链上的 symbol 谁都能写，"USDT " 或带零宽
// 字符的仿冒符号必须在入库前拦住。
func SanitizeText(value string, limit int) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("text is not valid UTF-8")
	}
	trimmed := strings.TrimSpace(value)
	if utf8.RuneCountInString(trimmed) > limit {
		return "", fmt.Errorf("text exceeds %d characters", limit)
	}
	for _, r := range trimmed {
		if r >= 0x20 && r <= 0x7e {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		return "", fmt.Errorf("text contains disallowed character U+%04X", r)
	}
	return trimmed, nil
}
