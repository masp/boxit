package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Profile defines HTTPS filtering rules for a boxit sandbox.
type Profile struct {
	AllowedDomains []string `json:"allowedDomains"` // nil = all allowed
	DenyDomains    []string `json:"denyDomains"`
	AllowedMethods []string `json:"allowedMethods"` // default: ["GET"]
}

// Default returns the built-in default profile: allow GET to any domain.
func Default() *Profile {
	return &Profile{
		AllowedMethods: []string{"GET"},
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
