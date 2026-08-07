package proxy

import "strings"

// Allowlist is a fixed set of origins this proxy will echo back in
// Access-Control-Allow-Origin. There is no wildcard support: a signed
// token only proves the bearer was handed a valid link, not that the page
// making the request is one we trust, so the Origin check is what stops
// an arbitrary third-party page from replaying a leaked token cross-site.
type Allowlist map[string]struct{}

// NewAllowlist builds an Allowlist from a comma-separated origin list,
// e.g. the ALLOWED_ORIGINS environment variable.
func NewAllowlist(raw string) Allowlist {
	allow := Allowlist{}
	for _, origin := range strings.Split(raw, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allow[origin] = struct{}{}
		}
	}
	return allow
}

func (a Allowlist) Allowed(origin string) bool {
	if origin == "" {
		return false
	}
	_, ok := a[origin]
	return ok
}
