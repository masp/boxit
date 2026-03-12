//go:build darwin || linux

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

// CADir returns the persistent CA directory (~/.boxit/).
func CADir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("proxy: %w", err)
	}
	return filepath.Join(home, ".boxit"), nil
}

// CACertPath returns the path to the persistent CA certificate.
func CACertPath() (string, error) {
	dir, err := CADir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca-cert.pem"), nil
}

// NewCA loads the persistent CA from ~/.boxit/ or generates a new one if missing/expired.
// The CA cert is also written to confDir for cert bundle building.
func NewCA(confDir string) (*CA, error) {
	caDir, err := CADir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("proxy: create CA dir: %w", err)
	}

	certPath := filepath.Join(caDir, "ca-cert.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")

	// Try loading existing CA
	ca, err := loadCA(certPath, keyPath)
	if err == nil {
		// Copy cert to confDir for bundle building
		confCertPath := filepath.Join(confDir, "boxit-ca-cert.pem")
		if err := os.WriteFile(confCertPath, ca.certPEM, 0644); err != nil {
			return nil, fmt.Errorf("proxy: write CA cert to confdir: %w", err)
		}
		return ca, nil
	}

	// Generate new CA
	ca, err = generateCA()
	if err != nil {
		return nil, err
	}

	// Persist to ~/.boxit/
	if err := os.WriteFile(certPath, ca.certPEM, 0644); err != nil {
		return nil, fmt.Errorf("proxy: write CA cert: %w", err)
	}
	keyPEM, err := marshalECKey(ca.key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("proxy: write CA key: %w", err)
	}

	// Copy cert to confDir for bundle building
	confCertPath := filepath.Join(confDir, "boxit-ca-cert.pem")
	if err := os.WriteFile(confCertPath, ca.certPEM, 0644); err != nil {
		return nil, fmt.Errorf("proxy: write CA cert to confdir: %w", err)
	}

	return ca, nil
}

// loadCA loads a CA from PEM files, returning an error if missing or expired.
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("proxy: invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Check if expired (with 1 hour buffer)
	if time.Now().Add(1 * time.Hour).After(cert.NotAfter) {
		return nil, fmt.Errorf("proxy: CA cert expired")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("proxy: invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// generateCA creates a new self-signed ECDSA P-256 CA with 1 year validity.
func generateCA() (*CA, error) {
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
		NotAfter:              now.Add(365 * 24 * time.Hour),
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

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

func marshalECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("proxy: marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
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
