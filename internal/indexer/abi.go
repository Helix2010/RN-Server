package indexer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	// transferTopic = keccak256("Transfer(address,address,uint256)")
	transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// multicall3 五条链同址（实测 eth_getCode 非空）。
	multicall3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
	// selectorAggregate3 = aggregate3((address,bool,bytes)[])
	selectorAggregate3 = "82ad56cb"
	// selectorGetEthBalance = getEthBalance(address)
	selectorGetEthBalance = "4d2301cc"
)

// topicAddress 把地址左补零到 32 字节，作 eth_getLogs 的 topic 过滤值。
func topicAddress(address string) string {
	return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(address, "0x"))
}

// addressFromTopic 从 32 字节 topic 取回小写地址。
func addressFromTopic(topic string) (string, error) {
	raw := strings.TrimPrefix(strings.ToLower(topic), "0x")
	if len(raw) != 64 {
		return "", fmt.Errorf("topic %q is not 32 bytes", topic)
	}
	if strings.Trim(raw[:24], "0") != "" {
		return "", fmt.Errorf("topic %q is not an address", topic)
	}
	return "0x" + raw[24:], nil
}

// uint256FromData 解 Transfer 日志的 data（一个 uint256）。
func uint256FromData(data string) (*big.Int, error) {
	raw := strings.TrimPrefix(strings.ToLower(data), "0x")
	if len(raw) != 64 {
		return nil, fmt.Errorf("log data %q is not one word", truncate(data, 80))
	}
	value, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return nil, errors.New("log data is not hex")
	}
	return value, nil
}

func word(value uint64) string { return fmt.Sprintf("%064x", value) }

func padAddress(address string) string {
	return strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(address, "0x"))
}

// encodeGetEthBalances 编 Multicall3.aggregate3 的调用数据：对每个地址调 getEthBalance。
// 布局：selector | 偏移(0x20) | 数组长度 N | N 个元组偏移 | 每个元组(target, allowFailure, bytes 偏移 0x60, bytes 长度 0x24, 数据 2 词)。
func encodeGetEthBalances(addresses []string) string {
	var b strings.Builder
	b.WriteString("0x" + selectorAggregate3)
	b.WriteString(word(0x20))
	b.WriteString(word(uint64(len(addresses))))
	// 每个元组固定 7 个词（0xe0 字节）：target, allowFailure, offset, length, data(2 词)= 6 词… 数据 0x24 字节补齐到 2 词
	const tupleWords = 6
	for index := range addresses {
		b.WriteString(word(uint64(len(addresses)*32 + index*tupleWords*32)))
	}
	for _, address := range addresses {
		b.WriteString(padAddress(multicall3))
		b.WriteString(word(1))
		b.WriteString(word(0x60))
		b.WriteString(word(0x24))
		b.WriteString(selectorGetEthBalance + padAddress(address) + strings.Repeat("0", 56))
	}
	return b.String()
}

// decodeAggregate3Balances 解 aggregate3 的返回：Result[] = (bool success, bytes returnData)[]。
func decodeAggregate3Balances(data string, count int) ([]*big.Int, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.New("aggregate3 result is not hex")
	}
	wordAt := func(offset int) (*big.Int, error) {
		if offset < 0 || offset+32 > len(raw) {
			return nil, errors.New("aggregate3 result truncated")
		}
		return new(big.Int).SetBytes(raw[offset : offset+32]), nil
	}
	arrayOffset, err := wordAt(0)
	if err != nil {
		return nil, err
	}
	base := int(arrayOffset.Int64())
	length, err := wordAt(base)
	if err != nil {
		return nil, err
	}
	if int(length.Int64()) != count {
		return nil, fmt.Errorf("aggregate3 returned %d results, expected %d", length.Int64(), count)
	}
	balances := make([]*big.Int, 0, count)
	for index := 0; index < count; index++ {
		tupleOffset, err := wordAt(base + 32 + index*32)
		if err != nil {
			return nil, err
		}
		tuple := base + 32 + int(tupleOffset.Int64())
		success, err := wordAt(tuple)
		if err != nil {
			return nil, err
		}
		if success.Sign() == 0 {
			return nil, fmt.Errorf("getEthBalance call %d failed", index)
		}
		dataOffset, err := wordAt(tuple + 32)
		if err != nil {
			return nil, err
		}
		dataStart := tuple + int(dataOffset.Int64())
		dataLength, err := wordAt(dataStart)
		if err != nil {
			return nil, err
		}
		if dataLength.Int64() != 32 {
			return nil, fmt.Errorf("getEthBalance call %d returned %d bytes", index, dataLength.Int64())
		}
		balance, err := wordAt(dataStart + 32)
		if err != nil {
			return nil, err
		}
		balances = append(balances, balance)
	}
	return balances, nil
}
