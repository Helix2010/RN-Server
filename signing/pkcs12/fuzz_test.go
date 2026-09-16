package pkcs12

import (
	"testing"
)

const fuzzPassword = "fuzz-password"

// FuzzDecode：任意输入不 panic；能解出条目时，每个条目都有证书且公钥与私钥一致。
// 种子用低迭代次数的真实文件，让变异能走到 MAC 之后的解析。
func FuzzDecode(f *testing.F) {
	// 调低总工作量上限：变异出来的大迭代次数会让每次执行花上几秒，模糊测试就停摆了
	maxTotalIterations = 200_000
	p := testPairs(f)[0]
	seed, err := encode(p.key, p.cert, "k", fuzzPassword, 2)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := Decode(data, fuzzPassword)
		if err != nil {
			return
		}
		for _, e := range entries {
			pub, ok := publicOf(e.PrivateKey)
			if e.Certificate == nil || !ok || !publicKeysEqual(e.Certificate.PublicKey, pub) {
				t.Fatalf("decoded an inconsistent entry: %v", e)
			}
		}
	})
}
