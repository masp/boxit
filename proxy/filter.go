package proxy

import (
	"strings"

	"github.com/masp/boxit/profile"
)

// Filter checks HTTP method and domain against profile rules.
type Filter struct {
	allowedMethods map[string]bool
	allowedDomains []string // nil = all allowed
	denyDomains    []string
}

// NewFilter builds a Filter from a profile.
func NewFilter(prof *profile.Profile) *Filter {
	methods := prof.AllowedMethods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	m := make(map[string]bool, len(methods))
	for _, method := range methods {
		m[strings.ToUpper(method)] = true
	}
	return &Filter{
		allowedMethods: m,
		allowedDomains: prof.AllowedDomains,
		denyDomains:    prof.DenyDomains,
	}
}

// CheckMethod returns a block reason if the method is not allowed, or "" if allowed.
func (f *Filter) CheckMethod(method string) string {
	method = strings.ToUpper(method)
	if f.allowedMethods[method] {
		return ""
	}
	allowed := make([]string, 0, len(f.allowedMethods))
	for m := range f.allowedMethods {
		allowed = append(allowed, m)
	}
	return "boxit: HTTP method " + method + " is not allowed. Allowed methods: " + strings.Join(allowed, ", ")
}

// CheckDomain returns a block reason if the domain is blocked, or "" if allowed.
func (f *Filter) CheckDomain(host string) string {
	// Check deny list first
	for _, d := range f.denyDomains {
		if domainMatches(host, d) {
			return "boxit: access to " + host + " is blocked by profile"
		}
	}

	// If allowlist is set, host must match at least one entry
	if f.allowedDomains != nil {
		for _, d := range f.allowedDomains {
			if domainMatches(host, d) {
				return ""
			}
		}
		return "boxit: access to " + host + " is blocked by profile"
	}

	return ""
}

// domainMatches checks if host matches a domain pattern (exact or suffix match).
func domainMatches(host, pattern string) bool {
	host = strings.ToLower(strings.TrimRight(host, "."))
	pattern = strings.ToLower(strings.TrimRight(pattern, "."))
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}
