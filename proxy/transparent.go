//go:build darwin || linux

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LogEntry records a single HTTP request observed by the proxy.
type LogEntry struct {
	Domain string
	Method string
	Path   string
}

// transparentProxy accepts TCP connections on a local port and classifies
// them as TLS or plaintext HTTP, then applies profile filtering.
type transparentProxy struct {
	listener net.Listener
	ca       *CA
	cache    *certCache
	filter   *Filter
	done     chan struct{}
	wg       sync.WaitGroup

	logMu  sync.Mutex
	reqLog []LogEntry
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

	slog.Debug("proxy: new connection", "remote", conn.RemoteAddr())

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		slog.Debug("proxy: peek failed", "err", err)
		return
	}

	pc := &prefixConn{reader: br, Conn: conn}

	switch {
	case first[0] == 0x16:
		slog.Debug("proxy: TLS ClientHello")
		tp.handleTLS(pc)
	case isHTTPMethod(first[0]):
		slog.Debug("proxy: HTTP request")
		tp.handleHTTP(pc, "", false)
	default:
		slog.Debug("proxy: unknown protocol, closing", "firstByte", first[0])
	}
}

func (tp *transparentProxy) handleTLS(conn net.Conn) {
	var sniHost string

	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost = hello.ServerName
			slog.Debug("proxy: TLS SNI", "host", sniHost)
			if reason := tp.filter.CheckDomain(sniHost); reason != "" {
				slog.Debug("proxy: TLS domain blocked", "host", sniHost, "reason", reason)
				return nil, fmt.Errorf("%s", reason)
			}
			return tp.ca.MintCert(tp.cache, sniHost)
		},
	})

	slog.Debug("proxy: TLS handshake starting")
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("proxy: TLS handshake failed", "err", err)
		return
	}
	defer tlsConn.Close()
	slog.Debug("proxy: TLS handshake complete", "host", sniHost)

	tp.handleHTTP(tlsConn, sniHost, true)
}

func (tp *transparentProxy) handleHTTP(conn net.Conn, defaultHost string, isTLS bool) {
	br := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		slog.Debug("proxy: waiting for HTTP request", "defaultHost", defaultHost, "isTLS", isTLS)
		req, err := http.ReadRequest(br)
		if err != nil {
			slog.Debug("proxy: HTTP read error", "err", err)
			return
		}
		slog.Debug("proxy: HTTP request", "method", req.Method, "host", req.Host, "url", req.URL.String())

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

		// Log the request
		tp.logRequest(hostOnly, req.Method, req.URL.Path)

		// Check method
		if reason := tp.filter.CheckMethod(req.Method, hostOnly); reason != "" {
			slog.Debug("proxy: method blocked", "method", req.Method, "host", hostOnly, "reason", reason)
			writeBlockResponse(conn, reason)
			return
		}

		// Check domain
		if reason := tp.filter.CheckDomain(hostOnly); reason != "" {
			slog.Debug("proxy: domain blocked", "host", hostOnly, "reason", reason)
			writeBlockResponse(conn, reason)
			return
		}

		tp.forwardRequest(conn, req, host, isTLS)
	}
}

// handleCONNECT handles the HTTP CONNECT method used by explicit proxies for HTTPS.
// It checks the domain, then establishes a raw TCP tunnel (no TLS interception).
// This avoids TLS fingerprint detection and certificate pinning issues.
// Method-level filtering is not possible through tunnels — only domain filtering applies.
func (tp *transparentProxy) handleCONNECT(conn net.Conn, req *http.Request) {
	host := req.Host
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	slog.Debug("proxy: CONNECT", "host", host)

	// Check domain before establishing tunnel
	if reason := tp.filter.CheckDomain(hostOnly); reason != "" {
		slog.Debug("proxy: CONNECT domain blocked", "host", hostOnly, "reason", reason)
		writeBlockResponse(conn, reason)
		return
	}

	// Check if this domain has method rules — if not, only GET is globally
	// allowed, and we can't verify methods inside a tunnel, so block.
	if reason := tp.filter.CheckMethod("POST", hostOnly); reason != "" {
		slog.Debug("proxy: CONNECT blocked (no POST rule for domain, can't filter inside tunnel)", "host", hostOnly)
		writeBlockResponse(conn, "boxit: HTTPS tunnel to "+hostOnly+" blocked — domain does not allow POST. Add a domain rule to allow.")
		return
	}

	// Log the tunneled connection
	tp.logRequest(hostOnly, "CONNECT", "")

	// Connect to upstream
	addr := host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = host + ":443"
	}

	upstream, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		slog.Debug("proxy: CONNECT upstream dial failed", "addr", addr, "err", err)
		writeBlockResponse(conn, fmt.Sprintf("boxit: upstream connection failed: %v", err))
		return
	}
	defer upstream.Close()

	// Tell the client the tunnel is established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	slog.Debug("proxy: CONNECT tunnel established", "host", host)

	// Bidirectional copy — raw TCP tunnel, no interception
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
	slog.Debug("proxy: CONNECT tunnel closed", "host", host)
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

	slog.Debug("proxy: forwarding", "method", req.Method, "host", host, "path", req.URL.Path, "upstream", addr)

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
		slog.Debug("proxy: upstream dial failed", "addr", addr, "err", err)
		writeBlockResponse(clientConn, fmt.Sprintf("boxit: upstream connection failed: %v", err))
		return
	}
	defer upstream.Close()

	// Ensure hop-by-hop headers are removed
	req.RequestURI = ""

	if err := req.Write(upstream); err != nil {
		slog.Debug("proxy: request write failed", "err", err)
		return
	}
	slog.Debug("proxy: request sent to upstream", "method", req.Method, "host", host)

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		slog.Debug("proxy: response read failed", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Debug("proxy: got response", "status", resp.StatusCode, "contentLength", resp.ContentLength, "transferEncoding", resp.TransferEncoding)

	if err := resp.Write(clientConn); err != nil {
		slog.Debug("proxy: response write to client failed", "err", err)
		return
	}
	slog.Debug("proxy: forward complete", "method", req.Method, "host", host, "status", resp.StatusCode)
}

func (tp *transparentProxy) logRequest(domain, method, path string) {
	tp.logMu.Lock()
	defer tp.logMu.Unlock()
	tp.reqLog = append(tp.reqLog, LogEntry{Domain: domain, Method: method, Path: path})
}

func (tp *transparentProxy) requestLog() []LogEntry {
	tp.logMu.Lock()
	defer tp.logMu.Unlock()
	return append([]LogEntry(nil), tp.reqLog...)
}

func (tp *transparentProxy) stop() {
	slog.Debug("proxy: closing listener")
	close(tp.done)
	tp.listener.Close()

	// Wait for in-flight connections with timeout
	slog.Debug("proxy: waiting for in-flight connections")
	ch := make(chan struct{})
	go func() {
		tp.wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
		slog.Debug("proxy: all connections drained")
	case <-time.After(5 * time.Second):
		slog.Debug("proxy: timed out waiting for connections, forcing shutdown")
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
