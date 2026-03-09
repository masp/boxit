//go:build darwin

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// transparentProxy accepts TCP connections on a local port and classifies
// them as TLS or plaintext HTTP, then applies profile filtering.
type transparentProxy struct {
	listener net.Listener
	ca       *CA
	cache    *certCache
	filter   *Filter
	done     chan struct{}
	wg       sync.WaitGroup
}

// prefixConn wraps a net.Conn with a bufio.Reader so that peeked bytes
// can be replayed for the TLS or HTTP handler.
type prefixConn struct {
	reader *bufio.Reader
	net.Conn
}

func (c *prefixConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func newTransparentProxy(port int, ca *CA, filter *Filter) (*transparentProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("proxy: listen: %w", err)
	}
	return &transparentProxy{
		listener: ln,
		ca:       ca,
		cache:    &certCache{certs: make(map[string]*tls.Certificate)},
		filter:   filter,
		done:     make(chan struct{}),
	}, nil
}

func (tp *transparentProxy) serve() {
	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			select {
			case <-tp.done:
				return
			default:
				continue
			}
		}
		tp.wg.Add(1)
		go func() {
			defer tp.wg.Done()
			tp.handleConn(conn)
		}()
	}
}

func (tp *transparentProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	pc := &prefixConn{reader: br, Conn: conn}

	switch {
	case first[0] == 0x16:
		// TLS ClientHello
		tp.handleTLS(pc)
	case isHTTPMethod(first[0]):
		tp.handleHTTP(pc, "", false)
	default:
		// Non-HTTP/HTTPS traffic — block by closing
	}
}

func (tp *transparentProxy) handleTLS(conn net.Conn) {
	var sniHost string

	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost = hello.ServerName
			if reason := tp.filter.CheckDomain(sniHost); reason != "" {
				return nil, fmt.Errorf("%s", reason)
			}
			return tp.ca.MintCert(tp.cache, sniHost)
		},
	})

	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	tp.handleHTTP(tlsConn, sniHost, true)
}

func (tp *transparentProxy) handleHTTP(conn net.Conn, defaultHost string, isTLS bool) {
	br := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		// Handle CONNECT method (explicit proxy mode for HTTPS)
		if req.Method == "CONNECT" {
			tp.handleCONNECT(conn, req)
			return
		}

		host := req.Host
		if host == "" {
			host = defaultHost
		}
		// Strip port from host for domain checking
		hostOnly := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostOnly = h
		}

		// Check method
		if reason := tp.filter.CheckMethod(req.Method); reason != "" {
			writeBlockResponse(conn, reason)
			return
		}

		// Check domain
		if reason := tp.filter.CheckDomain(hostOnly); reason != "" {
			writeBlockResponse(conn, reason)
			return
		}

		tp.forwardRequest(conn, req, host, isTLS)
	}
}

// handleCONNECT handles the HTTP CONNECT method used by explicit proxies for HTTPS.
// It sends 200 Connection Established, then performs TLS interception on the tunnel.
func (tp *transparentProxy) handleCONNECT(conn net.Conn, req *http.Request) {
	host := req.Host
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	// Check domain before establishing tunnel
	if reason := tp.filter.CheckDomain(hostOnly); reason != "" {
		writeBlockResponse(conn, reason)
		return
	}

	// Tell the client the tunnel is established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Now perform TLS interception on the tunneled connection
	tp.handleTLS(conn)
}

func (tp *transparentProxy) forwardRequest(clientConn net.Conn, req *http.Request, host string, isTLS bool) {
	// Determine upstream address
	addr := host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if isTLS {
			addr = host + ":443"
		} else {
			addr = host + ":80"
		}
	}

	var upstream net.Conn
	var err error

	if isTLS {
		upstream, err = tls.Dial("tcp", addr, &tls.Config{
			ServerName: hostWithoutPort(host),
		})
	} else {
		upstream, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		writeBlockResponse(clientConn, fmt.Sprintf("boxit: upstream connection failed: %v", err))
		return
	}
	defer upstream.Close()

	// Ensure hop-by-hop headers are removed
	req.RequestURI = ""

	if err := req.Write(upstream); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if err := resp.Write(clientConn); err != nil {
		return
	}
}

func (tp *transparentProxy) stop() {
	close(tp.done)
	tp.listener.Close()

	// Wait for in-flight connections with timeout
	ch := make(chan struct{})
	go func() {
		tp.wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
	}
}

func writeBlockResponse(conn net.Conn, reason string) {
	body := reason + "\n"
	resp := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n" +
		"\r\n" +
		body
	conn.Write([]byte(resp))
}

func isHTTPMethod(b byte) bool {
	// First byte of common HTTP methods: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE
	return b == 'G' || b == 'H' || b == 'P' || b == 'D' || b == 'O' || b == 'C' || b == 'T'
}

func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimRight(host, ".")
}
