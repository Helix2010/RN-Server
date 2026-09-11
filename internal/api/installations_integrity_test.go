package api

import (
	"encoding/json"
	"testing"
)

// 安全评审 N31：信号是**自报**的，所以"没上报"与"上报说干净"必须是两个值。
// 混成同一个，管理端上"有多少台 root 设备"这个数就直接是假的——旧版 App 会被
// 算成干净设备。
func TestDeviceIntegrityKeepsUnreportedApartFromClean(t *testing.T) {
	if encodeDeviceIntegrity(nil) != nil {
		t.Fatal("a missing report must be stored as NULL")
	}
	if encodeDeviceIntegrity(&deviceIntegrityReport{}) != nil {
		t.Fatal("a report where every probe failed must be NULL, not a clean device")
	}

	no, yes := false, true
	stored, ok := encodeDeviceIntegrity(&deviceIntegrityReport{Rooted: &no}).([]byte)
	if !ok {
		t.Fatal("a reported signal must be stored as JSON")
	}
	var decoded map[string]any
	if err := json.Unmarshal(stored, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["rooted"] != false {
		t.Fatalf("rooted=false did not round trip: %v", decoded)
	}
	// 探针失败的项保持 null，不被补成 false
	if decoded["emulator"] != nil {
		t.Fatalf("a probe that did not run became %v", decoded["emulator"])
	}
	if encodeDeviceIntegrity(&deviceIntegrityReport{Rooted: &yes, Emulator: &no}) == nil {
		t.Fatal("a rooted report was dropped")
	}
}
