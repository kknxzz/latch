package main

import "testing"

func TestUpgradeVersionPolicy(t *testing.T) {
	for _, test := range []struct {
		candidate, current string
		allowed            bool
	}{
		{"0.1.0", "0.1.0-dev", true}, {"0.1.0", "0.1.0", true}, {"0.1.1", "0.1.0", true}, {"1.0.0", "0.99.99", true},
		{"0.1.0", "0.1.1", false}, {"0.1.0-dev", "0.1.0", false}, {"1.0.0", "2.0.0-dev", false},
		{"01.1.0", "0.1.0", false}, {"1.2.3-beta", "1.2.0", false}, {"4294967296.0.0", "0.1.0", false}, {"1.2.3", "unknown", false},
	} {
		if err := checkUpgrade(test.candidate, test.current); (err == nil) != test.allowed {
			t.Errorf("%s from %s: %v", test.candidate, test.current, err)
		}
	}
}

func TestVersionPreflightDispatch(t *testing.T) {
	if err := run([]string{"version", "--check-upgrade", "0.0.9"}); err != nil {
		t.Fatal("preflight required server configuration", err)
	}
	if err := run([]string{"version", "--check-upgrade", "99.0.0"}); err == nil {
		t.Fatal("CLI permitted a downgrade")
	}
}
