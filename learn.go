//go:build darwin || linux

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/masp/boxit/profile"
	"github.com/masp/boxit/proxy"
	"github.com/masp/boxit/sandbox"
)

func runLearn(cwd string, args []string, saveName string) error {
	prof := profile.Permissive()

	// Cleanup stack
	var cleanups []func() error
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				slog.Debug("learn cleanup error", "err", err)
			}
		}
	}

	// 1. Create temp dir for cert bundle
	tmpDir, err := os.MkdirTemp("", "boxit-learn-")
	if err != nil {
		return err
	}
	cleanups = append(cleanups, func() error { return os.RemoveAll(tmpDir) })

	// 2. Start proxy with permissive profile (logs all requests)
	p, err := proxy.Start(prof)
	if err != nil {
		cleanup()
		return err
	}
	cleanups = append(cleanups, p.Stop)

	// 3. Build cert bundle
	certBundle, err := proxy.BuildCertBundle(p.ConfDir, tmpDir)
	if err != nil {
		cleanup()
		return err
	}

	// 4. Run sandbox with proxy env vars and trace enabled
	sandbox.SetTrace(true)
	envVars := proxy.CertEnvVars(certBundle)
	envVars = append(envVars, proxy.ProxyEnvVars(p.Port)...)

	fmt.Fprintln(os.Stderr, "boxit learn: running with permissive proxy (all network requests allowed and logged)")
	fmt.Fprintln(os.Stderr, "boxit learn: use the application normally, then exit when done")
	fmt.Fprintln(os.Stderr, "")

	cmdErr := sandbox.RunWithOptions(sandbox.Options{
		CWD:      cwd,
		Args:     args,
		ExtraEnv:  envVars,
		FilterEnv: []string{"CLAUDECODE", "CLAUDE_CODE_SSE_PORT"},
	})

	// 5. Collect proxy log before stopping
	reqLog := p.RequestLog()

	// 6. Stop proxy and clean up
	cleanup()

	// 7. Display results
	printNetworkSummary(reqLog)

	// 8. Generate and save/print profile
	generated := generateProfile(reqLog)
	if saveName != "" {
		if err := profile.Save(saveName, generated); err != nil {
			fmt.Fprintf(os.Stderr, "boxit learn: failed to save profile: %v\n", err)
		} else {
			home, _ := os.UserHomeDir()
			fmt.Fprintf(os.Stderr, "boxit learn: profile saved to %s/.boxit/%s.json\n", home, saveName)
		}
	} else {
		data, _ := json.MarshalIndent(generated, "", "  ")
		fmt.Fprintf(os.Stderr, "\nGenerated profile (use -save <name> to persist):\n%s\n", string(data))
	}

	return cmdErr
}

func printNetworkSummary(log []proxy.LogEntry) {
	type domainInfo struct {
		methods map[string]bool
		count   int
	}
	domains := make(map[string]*domainInfo)
	for _, entry := range log {
		d, ok := domains[entry.Domain]
		if !ok {
			d = &domainInfo{methods: make(map[string]bool)}
			domains[entry.Domain] = d
		}
		d.methods[entry.Method] = true
		d.count++
	}

	var names []string
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Fprintf(os.Stderr, "\n=== Network Activity (%d requests to %d domains) ===\n\n", len(log), len(names))
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "  (no HTTP/HTTPS requests observed)")
		fmt.Fprintln(os.Stderr, "  Note: only requests routed through http_proxy/https_proxy are captured.")
		fmt.Fprintln(os.Stderr, "  Run with sudo for transparent interception of all traffic.")
		return
	}

	fmt.Fprintf(os.Stderr, "  %-45s %-20s %s\n", "Domain", "Methods", "Requests")
	fmt.Fprintf(os.Stderr, "  %-45s %-20s %s\n",
		strings.Repeat("─", 45), strings.Repeat("─", 20), strings.Repeat("─", 8))
	for _, name := range names {
		d := domains[name]
		var methods []string
		for m := range d.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		fmt.Fprintf(os.Stderr, "  %-45s %-20s %d\n", name, strings.Join(methods, ", "), d.count)
	}
	fmt.Fprintln(os.Stderr)
}

func generateProfile(log []proxy.LogEntry) *profile.Profile {
	domainMethods := make(map[string]map[string]bool)
	for _, entry := range log {
		if _, ok := domainMethods[entry.Domain]; !ok {
			domainMethods[entry.Domain] = make(map[string]bool)
		}
		domainMethods[entry.Domain][entry.Method] = true
	}

	// Build domain rules for domains that need non-GET methods
	var rules []profile.DomainRule
	for domain, methods := range domainMethods {
		var nonGet []string
		for m := range methods {
			if strings.ToUpper(m) != "GET" {
				nonGet = append(nonGet, strings.ToUpper(m))
			}
		}
		if len(nonGet) > 0 {
			sort.Strings(nonGet)
			rules = append(rules, profile.DomainRule{
				Domain:  domain,
				Methods: nonGet,
			})
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Domain < rules[j].Domain
	})

	return &profile.Profile{
		AllowedMethods: []string{"GET"},
		DomainRules:    rules,
	}
}
