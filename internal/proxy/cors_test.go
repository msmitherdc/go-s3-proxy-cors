package proxy

import "testing"

func TestAllowlistExactMatch(t *testing.T) {
	allow := NewAllowlist("https://griddl.example.mil,http://localhost:3000")

	if !allow.Allowed("https://griddl.example.mil") {
		t.Error("expected exact origin to be allowed")
	}
	if !allow.Allowed("http://localhost:3000") {
		t.Error("expected exact origin to be allowed")
	}
	if allow.Allowed("https://evil.example.com") {
		t.Error("expected unlisted origin to be rejected")
	}
	if allow.Allowed("") {
		t.Error("expected empty origin to be rejected")
	}
}

func TestAllowlistCIDRMatch(t *testing.T) {
	allow := NewAllowlist("172.31.0.0/16, 10.0.0.0/8")

	tests := []struct {
		origin string
		want   bool
	}{
		{"https://172.31.5.10:3000", true},
		{"http://172.31.255.254", true},
		{"https://10.0.0.1", true},
		{"https://192.168.1.1", false},
		{"https://griddl.example.mil", false},
	}
	for _, tt := range tests {
		if got := allow.Allowed(tt.origin); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

func TestAllowlistMixedExactAndCIDR(t *testing.T) {
	allow := NewAllowlist("https://grid-alb.us-east-1.elb.amazonaws.com,172.31.0.0/16")

	if !allow.Allowed("https://grid-alb.us-east-1.elb.amazonaws.com") {
		t.Error("expected the exact ALB origin to be allowed")
	}
	if !allow.Allowed("https://172.31.5.10:8443") {
		t.Error("expected an origin inside the CIDR range to be allowed")
	}
	if allow.Allowed("https://172.32.0.1") {
		t.Error("expected an origin outside the CIDR range to be rejected")
	}
}

func TestAllowlistRejectsMalformedOrigin(t *testing.T) {
	allow := NewAllowlist("172.31.0.0/16")

	if allow.Allowed("not a url at all") {
		t.Error("expected a malformed origin to be rejected")
	}
	if allow.Allowed("https://not-an-ip-and-not-listed.example.com") {
		t.Error("expected a hostname origin with no CIDR match to be rejected")
	}
}
