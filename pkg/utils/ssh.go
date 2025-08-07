// pkg/utils/ssh.go

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig holds SSH connection configuration
type SSHConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	KeyFile  string
	Timeout  time.Duration
	// Privilege escalation settings
	Become       bool
	BecomeMethod string
	BecomeUser   string
	BecomePass   string
	BecomeFlags  string
}

// SSHConnection represents an SSH connection to a remote host
type SSHConnection struct {
	Config            *SSHConfig
	Client            *ssh.Client
	mu                sync.Mutex
	connected         bool
	persistentShell   *PersistentShell
	sessionPool       []*ssh.Session
	maxSessions       int
	currentSessionIdx int
}

// PersistentShell maintains a long-running shell session
type PersistentShell struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
	ready   bool
	mu      sync.Mutex
}

// NewSSHConnection creates a new SSH connection
func NewSSHConnection(config *SSHConfig) (*SSHConnection, error) {
	return &SSHConnection{
		Config:      config,
		maxSessions: 5, // Pool of 5 sessions
		sessionPool: make([]*ssh.Session, 0, 5),
	}, nil
}

// Connect establishes the SSH connection with session pooling
func (s *SSHConnection) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connected && s.Client != nil {
		// Test if connection is still alive
		if err := s.testConnectionLocked(); err == nil {
			return nil
		}
		// Connection is dead, close and reconnect
		s.closePersistentShellLocked()
		s.Client.Close()
		s.Client = nil
		s.connected = false
	}

	var authMethods []ssh.AuthMethod

	// Try SSH key authentication first
	if s.Config.KeyFile != "" {
		if keyAuth, err := s.getKeyAuth(); err == nil {
			authMethods = append(authMethods, keyAuth)
		}
	} else {
		// Try default SSH key locations
		homeDir, _ := os.UserHomeDir()
		defaultKeys := []string{
			filepath.Join(homeDir, ".ssh", "id_rsa"),
			filepath.Join(homeDir, ".ssh", "id_ed25519"),
			filepath.Join(homeDir, ".ssh", "id_ecdsa"),
		}

		for _, keyPath := range defaultKeys {
			if fileExists(keyPath) {
				if keyAuth, err := s.getKeyAuthFromFile(keyPath); err == nil {
					authMethods = append(authMethods, keyAuth)
					break
				}
			}
		}
	}

	// Add password authentication if provided
	if s.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.Config.Password))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication methods available")
	}

	// Configure SSH client
	sshConfig := &ssh.ClientConfig{
		User:            s.Config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.Config.Timeout,
	}

	// Parse port
	port := s.Config.Port
	if port == "" {
		port = "22"
	}

	address := fmt.Sprintf("%s:%s", s.Config.Host, port)

	// Connect with optimized settings
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %v", address, err)
	}

	// Enable TCP keepalive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true) // Disable Nagle for lower latency
	}

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake failed: %v", err)
	}

	s.Client = ssh.NewClient(sshConn, chans, reqs)
	s.connected = true

	// Initialize persistent shell for command execution
	if err := s.initializePersistentShell(); err != nil {
		// Not fatal - we can fall back to individual sessions
		// Silently ignore the error and continue
	}

	return nil
}

// initializePersistentShell creates a persistent shell session
func (s *SSHConnection) initializePersistentShell() error {
	session, err := s.Client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create shell session: %v", err)
	}

	// Set up pipes
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		session.Close()
		return err
	}

	// Start shell
	if err := session.Shell(); err != nil {
		session.Close()
		return err
	}

	s.persistentShell = &PersistentShell{
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		ready:   true,
	}

	// Setup shell environment
	setupCmds := []string{
		"export PS1='CMDPROMPT# '",
		"export LANG=C",
		"export LC_ALL=C",
		"set +o history",
		"unset HISTFILE",
	}

	// Pre-authenticate sudo if needed
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		escapedPass := strings.ReplaceAll(s.Config.BecomePass, "'", "'\\''")
		setupCmds = append(setupCmds, fmt.Sprintf("echo '%s' | sudo -S -v 2>/dev/null", escapedPass))
		// Keep sudo timestamp fresh
		setupCmds = append(setupCmds, "(while true; do sudo -v; sleep 50; done >/dev/null 2>&1 &)")
	}

	for _, cmd := range setupCmds {
		fmt.Fprintf(stdin, "%s\n", cmd)
	}

	// Give shell time to initialize
	time.Sleep(200 * time.Millisecond)

	return nil
}

// RunCommand executes a command - tries persistent shell first, falls back to new session
func (s *SSHConnection) RunCommand(name string, args ...string) (string, error) {
	return s.RunCommandWithTimeout(name, 30, args...)
}

// RunCommandWithTimeout executes a command with timeout
func (s *SSHConnection) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	s.mu.Lock()

	// Ensure we're connected
	if !s.connected || s.Client == nil {
		s.mu.Unlock()
		if err := s.Connect(); err != nil {
			return "", fmt.Errorf("not connected: %v", err)
		}
		s.mu.Lock()
	}

	// Try persistent shell first for speed
	if s.persistentShell != nil && s.persistentShell.ready {
		s.mu.Unlock()
		output, err := s.runInPersistentShell(name, timeout, args...)
		if err == nil {
			return output, nil
		}
		// Fall back to new session if persistent shell fails
		s.mu.Lock()
	}

	client := s.Client
	s.mu.Unlock()

	// Fallback: Create new session (original method)
	return s.runInNewSession(client, name, timeout, args...)
}

// runInPersistentShell executes command in the persistent shell
func (s *SSHConnection) runInPersistentShell(name string, timeout int, args ...string) (string, error) {
	s.persistentShell.mu.Lock()
	defer s.persistentShell.mu.Unlock()

	if !s.persistentShell.ready {
		return "", fmt.Errorf("persistent shell not ready")
	}

	// Build command
	cmd := s.buildCommand(name, args...)

	// Create unique marker
	marker := fmt.Sprintf("ENDCMD_%d", time.Now().UnixNano())

	// Execute with marker
	fullCmd := fmt.Sprintf("%s 2>&1; echo '%s'=$?", cmd, marker)
	fmt.Fprintf(s.persistentShell.stdin, "%s\n", fullCmd)

	// Read output until marker
	output := bytes.NewBuffer(nil)
	buf := make([]byte, 8192)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)

	for time.Now().Before(deadline) {
		// Non-blocking read with timeout
		readChan := make(chan int, 1)
		go func() {
			n, _ := s.persistentShell.stdout.Read(buf)
			readChan <- n
		}()

		select {
		case n := <-readChan:
			if n > 0 {
				output.Write(buf[:n])

				// Check for marker
				outputStr := output.String()
				if idx := strings.Index(outputStr, marker); idx >= 0 {
					// Extract output before marker
					result := outputStr[:idx]
					// Clean output
					result = s.cleanShellOutput(result)
					return result, nil
				}
			}
		case <-time.After(100 * time.Millisecond):
			// Continue waiting
		}
	}

	// Timeout - shell might be broken
	s.persistentShell.ready = false
	return "", fmt.Errorf("command timed out")
}

// runInNewSession creates a new SSH session for the command (fallback)
func (s *SSHConnection) runInNewSession(client *ssh.Client, name string, timeout int, args ...string) (string, error) {
	// Build command
	cmd := s.buildCommand(name, args...)

	// Add timeout wrapper
	if timeout > 0 {
		cmd = fmt.Sprintf("timeout %d %s", timeout, cmd)
	}

	// Handle sudo password
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		escapedPass := strings.ReplaceAll(s.Config.BecomePass, "'", "'\\''")
		cmd = fmt.Sprintf("printf '%%s\\n' '%s' | %s", escapedPass, cmd)
	}

	// Create new session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Run command
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		// Check if we got output despite error
		if len(output) > 0 {
			return s.cleanSudoPrompts(string(output)), nil
		}
		return "", err
	}

	return s.cleanSudoPrompts(string(output)), nil
}

// RunCommandWithContext executes command with context
func (s *SSHConnection) RunCommandWithContext(ctx context.Context, name string, timeoutSecs int, args ...string) (string, error) {
	resultChan := make(chan struct {
		output string
		err    error
	}, 1)

	go func() {
		output, err := s.RunCommandWithTimeout(name, timeoutSecs, args...)
		resultChan <- struct {
			output string
			err    error
		}{output, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-resultChan:
		return result.output, result.err
	}
}

// buildCommand builds the command string with privilege escalation
func (s *SSHConnection) buildCommand(name string, args ...string) string {
	// Build base command
	baseCmd := name
	if len(args) > 0 {
		escapedArgs := make([]string, len(args))
		for i, arg := range args {
			if strings.ContainsAny(arg, " \t\n'\"\\$`") {
				escapedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
			} else {
				escapedArgs[i] = arg
			}
		}
		baseCmd = fmt.Sprintf("%s %s", name, strings.Join(escapedArgs, " "))
	}

	// Apply privilege escalation
	if s.Config.Become {
		switch s.Config.BecomeMethod {
		case "sudo":
			sudoCmd := "sudo"
			if s.Config.BecomeFlags != "" {
				sudoCmd += " " + s.Config.BecomeFlags
			}
			if s.Config.BecomePass != "" {
				sudoCmd += " -S"
			} else {
				sudoCmd += " -n"
			}
			if s.Config.BecomeUser != "" && s.Config.BecomeUser != "root" {
				sudoCmd += fmt.Sprintf(" -u %s", s.Config.BecomeUser)
			}
			baseCmd = fmt.Sprintf("%s %s", sudoCmd, baseCmd)

		case "su":
			if s.Config.BecomeUser != "" && s.Config.BecomeUser != "root" {
				baseCmd = fmt.Sprintf("su - %s -c '%s'", s.Config.BecomeUser, baseCmd)
			} else {
				baseCmd = fmt.Sprintf("su - -c '%s'", baseCmd)
			}

		case "doas":
			doasCmd := "doas"
			if s.Config.BecomeUser != "" && s.Config.BecomeUser != "root" {
				doasCmd += fmt.Sprintf(" -u %s", s.Config.BecomeUser)
			}
			baseCmd = fmt.Sprintf("%s %s", doasCmd, baseCmd)
		}
	}

	return baseCmd
}

// cleanSudoPrompts removes sudo password prompts
func (s *SSHConnection) cleanSudoPrompts(output string) string {
	lines := strings.Split(output, "\n")
	var cleanLines []string
	for _, line := range lines {
		if !strings.Contains(line, "[sudo] password") &&
			!strings.Contains(line, "Password:") &&
			!strings.Contains(line, "password for") {
			cleanLines = append(cleanLines, line)
		}
	}
	return strings.Join(cleanLines, "\n")
}

// cleanShellOutput removes shell artifacts
func (s *SSHConnection) cleanShellOutput(output string) string {
	lines := strings.Split(output, "\n")
	var cleanLines []string

	for _, line := range lines {
		// Skip prompts and artifacts
		if strings.HasPrefix(line, "CMDPROMPT#") ||
			strings.Contains(line, "[sudo] password") ||
			strings.Contains(line, "Password:") ||
			strings.HasPrefix(line, "+ ") ||
			strings.HasPrefix(line, "++ ") {
			continue
		}
		cleanLines = append(cleanLines, line)
	}

	return strings.TrimSpace(strings.Join(cleanLines, "\n"))
}

// closePersistentShellLocked closes the persistent shell (must hold lock)
func (s *SSHConnection) closePersistentShellLocked() {
	if s.persistentShell != nil {
		s.persistentShell.stdin.Close()
		s.persistentShell.session.Close()
		s.persistentShell = nil
	}
}

// Close closes the SSH connection
func (s *SSHConnection) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closePersistentShellLocked()

	if s.Client != nil {
		err := s.Client.Close()
		s.Client = nil
		s.connected = false
		return err
	}
	return nil
}

// TestConnection tests if the SSH connection is working
func (s *SSHConnection) TestConnection() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.testConnectionLocked()
}

// testConnectionLocked tests connection without locking
func (s *SSHConnection) testConnectionLocked() error {
	if s.Client == nil {
		return fmt.Errorf("client is nil")
	}

	// Quick test with persistent shell if available
	if s.persistentShell != nil && s.persistentShell.ready {
		return nil
	}

	// Fallback to creating test session
	session, err := s.Client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create test session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo test")
	if err != nil {
		return fmt.Errorf("test command failed: %v", err)
	}

	if !strings.Contains(string(output), "test") {
		return fmt.Errorf("unexpected output from test command")
	}

	return nil
}

// getKeyAuth loads SSH key authentication
func (s *SSHConnection) getKeyAuth() (ssh.AuthMethod, error) {
	return s.getKeyAuthFromFile(s.Config.KeyFile)
}

// getKeyAuthFromFile loads SSH key from file
func (s *SSHConnection) getKeyAuthFromFile(keyPath string) (ssh.AuthMethod, error) {
	// Expand tilde
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, _ := os.UserHomeDir()
		keyPath = filepath.Join(homeDir, keyPath[2:])
	}

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	return ssh.PublicKeys(signer), nil
}

// fileExists checks if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
