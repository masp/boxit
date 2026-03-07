//go:build darwin

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA holds a self-signed root certificate and key used to mint per-host leaf certs.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

type certCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

// NewCA generates a self-signed ECDSA P-256 CA and writes boxit-ca-cert.pem to confDir.
func NewCA(confDir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Boxit Proxy CA",
			Organization: []string{"Boxit"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("proxy: create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write CA cert to confDir
	certPath := filepath.Join(confDir, "boxit-ca-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("proxy: write CA cert: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// MintCert generates a leaf certificate for the given hostname, signed by this CA.
// Results are cached by hostname.
func (ca *CA) MintCert(cache *certCache, hostname string) (*tls.Certificate, error) {
	cache.mu.RLock()
	if c, ok := cache.certs[hostname]; ok {
		cache.mu.RUnlock()
		return c, nil
	}
	cache.mu.RUnlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now,
		NotAfter:     now.Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("proxy: create leaf cert: %w", err)
	}

	leaf := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	cache.mu.Lock()
	cache.certs[hostname] = leaf
	cache.mu.Unlock()

	return leaf, nil
}
