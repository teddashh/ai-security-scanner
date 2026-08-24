package main

import "testing"

func TestParsePositiveInt64(t *testing.T) {
	value, err := parsePositiveInt64("1786368462")
	if err != nil || value != 1786368462 {
		t.Fatalf("valid source epoch rejected: %d, %v", value, err)
	}
	for _, invalid := range []string{"", "0", "-1", "1.5", "9223372036854775808"} {
		if _, err := parsePositiveInt64(invalid); err == nil {
			t.Fatalf("invalid source epoch %q accepted", invalid)
		}
	}
}
