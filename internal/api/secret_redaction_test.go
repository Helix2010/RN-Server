package api

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// 与 RN-App 共享的契约向量：两边的出口脱敏必须逐字节一致，否则 redaction_hits
// 就从"客户端那遍没拦住"退化成"两边算法不一样"。
func TestSecretRedactionMatchesTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/secret-redaction.v1.json")
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var vectors struct {
		Redacted         string `json:"redacted"`
		MinMnemonicWords int    `json:"minMnemonicWords"`
		Cases            []struct {
			Name     string   `json:"name"`
			Input    string   `json:"input"`
			Redacted string   `json:"redacted"`
			Kinds    []string `json:"kinds"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode shared vectors: %v", err)
	}
	if vectors.Redacted != redactedSecret || vectors.MinMnemonicWords != minMnemonicWords {
		t.Fatalf("shared marker/threshold drifted: %q %d", vectors.Redacted, vectors.MinMnemonicWords)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("shared vectors are empty")
	}
	for _, tc := range vectors.Cases {
		got, hit := redactSecrets(tc.Input)
		if got != tc.Redacted {
			t.Errorf("%s: redacted\n got  %q\n want %q", tc.Name, got, tc.Redacted)
		}
		if hit != (len(tc.Kinds) > 0) {
			t.Errorf("%s: hit=%v but kinds=%v", tc.Name, hit, tc.Kinds)
		}
		if kinds := findSecretKinds(tc.Input); !reflect.DeepEqual(kinds, tc.Kinds) {
			t.Errorf("%s: kinds got %v want %v", tc.Name, kinds, tc.Kinds)
		}
	}
}

func TestBIP39WordlistIsComplete(t *testing.T) {
	if len(bip39English) != 2048 {
		t.Fatalf("BIP-39 English wordlist must have 2048 distinct words, got %d", len(bip39English))
	}
	for _, word := range []string{"abandon", "zoo", "secret", "then"} {
		if _, ok := bip39English[word]; !ok {
			t.Fatalf("wordlist is missing %q", word)
		}
	}
}
