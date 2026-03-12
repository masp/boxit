package proxy

import (
	"strings"

	"github.com/masp/boxit/profile"
)

// domainMethods holds the parsed, uppercased method set for a domain pattern.
type domainMethods struct {
	pattern string
	methods map[string]bool
}

// Filter checks HTTP method and domain against profile rules.
type Filter struct {
	allowedMethods map[string]bool   // globally allowed methods
	allowedDomains []string          // nil = all domains allowed
	denyDomains    []string
	domainRules    []domainMethods   // per-domain method overrides
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

	var rules []domainMethods
	for _, r := range prof.DomainRules {
		dm := domainMethods{
			pattern: r.Domain,
			methods: make(map[string]bool, len(r.Methods)),
		}
		for _, method := range r.Methods {
			dm.methods[strings.ToUpper(method)] = true
		}
		rules = append(rules, dm)
	}

	return &Filter{
		allowedMethods: m,
		allowedDomains: prof.AllowedDomains,
		denyDomains:    prof.DenyDomains,
		domainRules:    rules,
	}
}

// CheckMethod returns a block reason if the method is not allowed for the given host,
// or "" if allowed.
func (f *Filter) CheckMethod(method, host string) string {
	method = strings.ToUpper(method)

	// Globally allowed methods pass unconditionally.
	if f.allowedMethods[method] {
		return ""
	}

	// Check per-domain rules.
	for _, rule := range f.domainRules {
		if domainMatches(host, rule.pattern) && rule.methods[method] {
			return ""
		}
	}

	return "boxit: HTTP method " + method + " to " + host + " is not allowed"
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

// domainMatches checks if host matches a domain pattern.
// It matches exactly or as a subdomain suffix:
//
//	domainMatches("api.anthropic.com", "anthropic.com")  → true
//	domainMatches("anthropic.com", "anthropic.com")      → true
//	domainMatches("notanthropic.com", "anthropic.com")   → false
func domainMatches(host, pattern string) bool {
	host = strings.ToLower(strings.TrimRight(host, "."))
	pattern = strings.ToLower(strings.TrimRight(pattern, "."))
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}
