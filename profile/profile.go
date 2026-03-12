package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DomainRule specifies which HTTP methods are allowed for a domain pattern.
// The domain pattern matches exactly or as a suffix (e.g. "googleapis.com"
// matches "generativelanguage.googleapis.com").
type DomainRule struct {
	Domain  string   `json:"domain"`
	Methods []string `json:"methods"`
}

// Profile defines HTTPS filtering rules for a boxit sandbox.
type Profile struct {
	AllowedDomains []string `json:"allowedDomains,omitempty"` // nil = all allowed
	DenyDomains    []string `json:"denyDomains,omitempty"`
	AllowedMethods []string `json:"allowedMethods"`           // globally allowed methods (default: ["GET"])

	// DomainRules specifies per-domain method overrides. If a request's domain
	// matches a rule, that rule's methods are allowed in addition to AllowedMethods.
	DomainRules []DomainRule `json:"domainRules,omitempty"`
}

// DefaultDomainRules are rules for well-known AI tool APIs that need POST
// to function (sending messages, completions, etc.).
var DefaultDomainRules = []DomainRule{
	// AI API endpoints
	{Domain: "anthropic.com", Methods: []string{"POST"}},
	{Domain: "googleapis.com", Methods: []string{"POST"}},
	{Domain: "openai.com", Methods: []string{"POST"}},
	{Domain: "chatgpt.com", Methods: []string{"POST"}},
	// Kiro (AWS-backed)
	{Domain: "amazonaws.com", Methods: []string{"POST"}},
	{Domain: "kiro.dev", Methods: []string{"POST"}},
	// Telemetry/logging used by AI tools
	{Domain: "datadoghq.com", Methods: []string{"POST"}},
}

// Permissive returns a profile that allows all HTTP methods to all domains.
// Used by "boxit learn" to observe traffic without blocking anything.
func Permissive() *Profile {
	return &Profile{
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
	}
}

// Default returns the built-in default profile: allow GET to any domain,
// POST only to known AI API endpoints.
func Default() *Profile {
	return &Profile{
		AllowedMethods: []string{"GET"},
		DomainRules:    DefaultDomainRules,
	}
}

// Load reads a profile from ~/.boxit/<name>.json.
func Load(name string) (*Profile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	path := filepath.Join(home, ".boxit", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if len(p.AllowedMethods) == 0 {
		p.AllowedMethods = []string{"GET"}
	}
	return &p, nil
}

// NeedsProxy reports whether this profile requires the HTTPS proxy.
// A nil profile or one with only the default GET method and no domain
// restrictions still needs the proxy to block non-GET methods.
func (p *Profile) NeedsProxy() bool {
	return true
}

// Save writes the profile to ~/.boxit/<name>.json.
func Save(name string, p *Profile) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	dir := filepath.Join(home, ".boxit")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	return nil
}

// WriteJSON writes the profile to a temporary file and returns the path.
func (p *Profile) WriteJSON(dir string) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "boxit-profile-*.json")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}
