// pkg/utils/ssh.go

package utils

import (
	"bytes"
	"context"
	"fmt"
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
	Config    *SSHConfig
	Client    *ssh.Client
	mu        sync.Mutex
	connected bool
}

// NewSSHConnection creates a new SSH connection
func NewSSHConnection(config *SSHConfig) (*SSHConnection, error) {
	return &SSHConnection{
		Config: config,
	}, nil
}

// Connect establishes the SSH connection with retry logic
func (s *SSHConnection) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connected && s.Client != nil {
		// Test if connection is still alive
		if err := s.testConnectionLocked(); err == nil {
			return nil
		}
		// Connection is dead, close and reconnect
		s.Client.Close()
		s.Client = nil
		s.connected = false
	}

	var authMethods []ssh.AuthMethod

	// Add password authentication if password is provided
	if s.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.Config.Password))
	}

	// ALSO try SSH key authentication (not else if!)
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
			if _, err := os.Stat(keyPath); err == nil {
				if keyAuth, err := s.getKeyAuthFromFile(keyPath); err == nil {
					authMethods = append(authMethods, keyAuth)
					break
				}
			}
		}
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication methods available")
	}

	// Configure SSH client
	sshConfig := &ssh.ClientConfig{
		User:            s.Config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, verify host key
		Timeout:         s.Config.Timeout,
	}

	// Parse port
	port := s.Config.Port
	if port == "" {
		port = "22"
	}

	// Connect with retry logic
	address := fmt.Sprintf("%s:%s", s.Config.Host, port)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second * 2) // Wait before retry
		}

		// Create a context with timeout for the connection attempt
		ctx, cancel := context.WithTimeout(context.Background(), s.Config.Timeout)
		defer cancel()

		// Dial with context
		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			lastErr = fmt.Errorf("failed to dial %s: %v", address, err)
			continue
		}

		// Perform SSH handshake
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshConfig)
		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("SSH handshake failed: %v", err)
			continue
		}

		s.Client = ssh.NewClient(sshConn, chans, reqs)
		s.connected = true

		// Test the connection
		if err := s.testConnectionLocked(); err != nil {
			s.Client.Close()
			s.Client = nil
			s.connected = false
			lastErr = fmt.Errorf("connection test failed: %v", err)
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to connect after 3 attempts: %v", lastErr)
}

// getKeyAuth loads SSH key authentication from the configured key file
func (s *SSHConnection) getKeyAuth() (ssh.AuthMethod, error) {
	return s.getKeyAuthFromFile(s.Config.KeyFile)
}

// getKeyAuthFromFile loads SSH key authentication from a specific file
func (s *SSHConnection) getKeyAuthFromFile(keyPath string) (ssh.AuthMethod, error) {
	// Expand tilde in path
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, _ := os.UserHomeDir()
		keyPath = filepath.Join(homeDir, keyPath[2:])
	}

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	// Parse the private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// Try with empty passphrase
		// In production, you'd want to handle passphrase-protected keys
		return nil, fmt.Errorf("unable to parse private key (it may be passphrase-protected): %v", err)
	}

	return ssh.PublicKeys(signer), nil
}

// RunCommand executes a command on the remote host with proper timeout
func (s *SSHConnection) RunCommand(name string, args ...string) (string, error) {
	// Use a default timeout of 30 seconds for all commands
	return s.RunCommandWithContext(context.Background(), name, 30, args...)
}

// RunCommandWithTimeout executes a command with a specific timeout
func (s *SSHConnection) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	return s.RunCommandWithContext(ctx, name, timeout, args...)
}

// RunCommandWithContext executes a command with context for cancellation
func (s *SSHConnection) RunCommandWithContext(ctx context.Context, name string, timeoutSecs int, args ...string) (string, error) {
	s.mu.Lock()
	if !s.connected || s.Client == nil {
		s.mu.Unlock()
		// Try to reconnect
		if err := s.Connect(); err != nil {
			return "", fmt.Errorf("SSH client not connected and reconnection failed: %v", err)
		}
		s.mu.Lock()
	}
	client := s.Client
	s.mu.Unlock()

	// Build the command
	cmd := s.buildCommand(name, args...)

	// Add timeout wrapper to the command itself
	if timeoutSecs > 0 {
		cmd = fmt.Sprintf("timeout %d %s", timeoutSecs, cmd)
	}

	// Handle sudo with password using a more reliable method
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		// Use printf to avoid echo issues and pipe to sudo
		escapedPass := strings.ReplaceAll(s.Config.BecomePass, "'", "'\\''")
		cmd = fmt.Sprintf("printf '%%s\\n' '%s' | %s", escapedPass, cmd)
	}

	// Create session with timeout
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Set up output buffers
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Start the command
	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}

	// Wait for command completion or context cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		// Context cancelled or timed out
		session.Signal(ssh.SIGTERM)
		time.Sleep(100 * time.Millisecond)
		session.Signal(ssh.SIGKILL)
		session.Close()
		return stdout.String(), fmt.Errorf("command timed out after %d seconds", timeoutSecs)

	case err := <-done:
		if err != nil {
			// Check if we got output despite error
			output := stdout.String()
			if output != "" {
				// Clean sudo prompts from output
				output = s.cleanSudoPrompts(output)
				return output, nil
			}

			// Check stderr for meaningful errors
			stderrStr := strings.TrimSpace(stderr.String())
			if stderrStr != "" && !strings.Contains(stderrStr, "password") && !strings.Contains(stderrStr, "sudo") {
				return output, fmt.Errorf("command failed: %v (stderr: %s)", err, stderrStr)
			}

			// Check if it was a timeout
			if strings.Contains(err.Error(), "124") {
				return output, fmt.Errorf("command timed out after %d seconds", timeoutSecs)
			}

			return output, fmt.Errorf("command failed: %v", err)
		}

		// Success - clean and return output
		output := stdout.String()
		return s.cleanSudoPrompts(output), nil
	}
}

// cleanSudoPrompts removes sudo password prompts from output
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

// buildCommand builds the command string with privilege escalation if needed
func (s *SSHConnection) buildCommand(name string, args ...string) string {
	// Build base command
	baseCmd := name
	if len(args) > 0 {
		// Properly escape arguments
		escapedArgs := make([]string, len(args))
		for i, arg := range args {
			// Escape special characters if needed
			if strings.ContainsAny(arg, " \t\n'\"\\$`") {
				escapedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
			} else {
				escapedArgs[i] = arg
			}
		}
		baseCmd = fmt.Sprintf("%s %s", name, strings.Join(escapedArgs, " "))
	}

	// Apply privilege escalation if configured
	if s.Config.Become {
		switch s.Config.BecomeMethod {
		case "sudo":
			sudoCmd := "sudo"

			// Add flags if specified
			if s.Config.BecomeFlags != "" {
				sudoCmd += " " + s.Config.BecomeFlags
			}

			// Add -S flag if password is provided (read from stdin)
			if s.Config.BecomePass != "" {
				sudoCmd += " -S" // -S for stdin
			} else {
				// Add -n flag if no password (non-interactive)
				sudoCmd += " -n"
			}

			// Add user if not root
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

// Close closes the SSH connection
func (s *SSHConnection) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

// testConnectionLocked tests connection without locking (must be called with lock held)
func (s *SSHConnection) testConnectionLocked() error {
	if s.Client == nil {
		return fmt.Errorf("client is nil")
	}

	// Create a session to test the connection
	session, err := s.Client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create test session: %v", err)
	}
	defer session.Close()

	// Run a simple echo command
	output, err := session.Output("echo test")
	if err != nil {
		return fmt.Errorf("test command failed: %v", err)
	}

	if !strings.Contains(string(output), "test") {
		return fmt.Errorf("unexpected output from test command")
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
