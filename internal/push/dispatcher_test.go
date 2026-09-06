package push

import "testing"

func TestDecodeSecretSupportsBase64AndEscapedPem(t *testing.T) {
	if got := string(decodeSecret("aGVsbG8=")); got != "hello" {
		t.Fatalf("base64 decode = %q", got)
	}
	if got := string(decodeSecret(`line1\nline2`)); got != "line1\nline2" {
		t.Fatalf("escaped pem decode = %q", got)
	}
}

func TestTargetInstallationsReadsPayloadList(t *testing.T) {
	if got := targetInstallations(map[string]any{"targetInstallationIds": []any{"inst_a", " ", "inst_b", 7}}); len(got) != 2 || got[0] != "inst_a" || got[1] != "inst_b" {
		t.Fatalf("targets = %v", got)
	}
	if got := targetInstallations(map[string]any{"chain": "monad"}); len(got) != 0 {
		t.Fatalf("no list must mean everyone: %v", got)
	}
}

func TestFormatAmountTruncatesToDisplayDecimals(t *testing.T) {
	cases := []struct {
		raw               string
		decimals, display int
		want              string
	}{
		{"1500000", 6, 2, "1.5"},
		{"1999999", 6, 2, "1.99"},
		{"5", 6, 2, "0"},
		{"1000000000000000000", 18, 4, "1"},
		{"123456789000000000000", 18, 4, "123.4567"},
		{"42", 0, 0, "42"},
		{"x", 6, 2, "x"},
	}
	for _, item := range cases {
		if got := formatAmount(item.raw, item.decimals, item.display); got != item.want {
			t.Fatalf("formatAmount(%s,%d,%d) = %q, want %q", item.raw, item.decimals, item.display, got, item.want)
		}
	}
}

func TestTransferPlaceholdersFillCopy(t *testing.T) {
	values := transferPlaceholders(map[string]any{"amountRaw": "2500000", "decimals": float64(6), "displayDecimals": float64(2), "symbol": "USDC", "chainName": "OP Sepolia"})
	if got := fillPlaceholders("{chain} 上收到 {amount} {symbol}。", values); got != "OP Sepolia 上收到 2.5 USDC。" {
		t.Fatalf("filled = %q", got)
	}
}
