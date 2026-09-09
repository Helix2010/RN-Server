package api

import "testing"

func TestParseByteRange(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		size      int64
		wantOK    bool
		wantSat   bool
		wantStart int64
		wantEnd   int64
	}{
		{"no header", "", 100, false, false, 0, 0},
		{"open ended resume", "bytes=40-", 100, true, true, 40, 99},
		{"closed range", "bytes=10-19", 100, true, true, 10, 19},
		{"end clamped to size", "bytes=90-500", 100, true, true, 90, 99},
		{"suffix", "bytes=-30", 100, true, true, 70, 99},
		{"suffix larger than file", "bytes=-500", 100, true, true, 0, 99},
		{"start beyond size", "bytes=100-", 100, true, false, 0, 0},
		{"multi range not supported", "bytes=0-1,5-6", 100, false, false, 0, 0},
		{"garbage", "bytes=a-b", 100, false, false, 0, 0},
		{"unknown size", "bytes=0-", -1, false, false, 0, 0},
		{"end before start", "bytes=20-10", 100, false, false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok, sat := parseByteRange(tc.header, tc.size)
			if ok != tc.wantOK || sat != tc.wantSat {
				t.Fatalf("ok=%v sat=%v, want ok=%v sat=%v", ok, sat, tc.wantOK, tc.wantSat)
			}
			if ok && sat && (r.start != tc.wantStart || r.end != tc.wantEnd) {
				t.Fatalf("range %d-%d, want %d-%d", r.start, r.end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}
