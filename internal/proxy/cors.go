package proxy

import (
	"net"
	"net/url"
	"strings"
)

// Allowlist is a fixed set of trusted origins this proxy will echo back
// in Access-Control-Allow-Origin, given either as exact origin strings
// (scheme://host[:port] - for callers with a real domain name, e.g. an
// external ALB) or as bare CIDR ranges (for callers reachable only by
// private IP, with no domain name at all - the common case for
// internal-only traffic, where the page's own Origin header is
// literally an IP like https://172.31.5.10:3000 rather than a
// hostname). There is no wildcard support: a signed token only proves
// the bearer was handed a valid link, not that the page making the
// request is one we trust, so the Origin check is what stops an
// arbitrary third-party page from replaying a leaked token cross-site.
type Allowlist struct {
	exact map[string]struct{}
	cidrs []*net.IPNet
}

// NewAllowlist builds an Allowlist from a comma-separated list mixing
// exact origins and CIDR ranges, e.g. the ALLOWED_ORIGINS environment
// variable: "https://grid-alb.us-east-1.elb.amazonaws.com,172.31.0.0/16".
// Each entry is tried as a CIDR first; anything that doesn't parse as
// one is treated as an exact origin string instead.
func NewAllowlist(raw string) Allowlist {
	allow := Allowlist{exact: map[string]struct{}{}}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			allow.cidrs = append(allow.cidrs, cidr)
			continue
		}
		allow.exact[entry] = struct{}{}
	}
	return allow
}

// Allowed reports whether origin - the raw value of a request's Origin
// header - is trusted: either an exact string match, or, when origin's
// host is a bare IP literal rather than a domain name, contained in one
// of the configured CIDR ranges.
func (a Allowlist) Allowed(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := a.exact[origin]; ok {
		return true
	}
	return a.allowedByCIDR(origin)
}

func (a Allowlist) allowedByCIDR(origin string) bool {
	if len(a.cidrs) == 0 {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return false
	}
	for _, cidr := range a.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
