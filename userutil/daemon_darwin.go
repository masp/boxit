//go:build darwin

package userutil

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const SocketPath = "/var/run/boxit_daemon.sock"

// RunDaemon starts the background daemon for managing temp users.
func RunDaemon() error {
	os.Remove(SocketPath)
	l, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(SocketPath)

	if err := os.Chmod(SocketPath, 0600); err != nil {
		return err
	}

	var wg sync.WaitGroup
	var activeMu sync.Mutex
	activeCount := 0
	var createMu sync.Mutex

	idleTimer := time.NewTimer(5 * time.Minute)

	go func() {
		<-idleTimer.C
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}

		activeMu.Lock()
		activeCount++
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		activeMu.Unlock()

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()

			handleClient(c, &createMu)

			activeMu.Lock()
			activeCount--
			if activeCount == 0 {
				idleTimer.Reset(5 * time.Minute)
			}
			activeMu.Unlock()
		}(conn)
	}

	wg.Wait()
	return nil
}

type reply struct {
	Username string
	UID      int
	Error    string
}

func handleClient(conn net.Conn, createMu *sync.Mutex) {
	reader := bufio.NewReader(conn)
	cmd, err := reader.ReadString('\n')
	if err != nil || cmd != "ALLOC\n" {
		return
	}

	createMu.Lock()
	username, uid, err := createTempUserInternal()
	createMu.Unlock()

	enc := json.NewEncoder(conn)

	if err != nil {
		enc.Encode(reply{Error: err.Error()})
		return
	}

	defer func() {
		if err := cleanupTempUserInternal(username); err != nil {
			log.Printf("failed to cleanup user %s: %v", username, err)
		}
	}()

	if err := enc.Encode(reply{Username: username, UID: uid}); err != nil {
		return
	}

	// Keep the connection open until the client disconnects or crashes
	io.Copy(io.Discard, conn)
}
