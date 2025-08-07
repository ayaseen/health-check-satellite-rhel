// pkg/utils/ssh.go

package utils

import (
	"bytes"
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
	Host         string
	Port         string
	User         string
	Password     string
	KeyFile      string
	Timeout      time.Duration
	Become       bool
	BecomeMethod string
	BecomeUser   string
	BecomePass   string
	BecomeFlags  string
}

// SSHConnection represents an SSH connection
type SSHConnection struct {
	Config    *SSHConfig
	Client    *ssh.Client
	mu        sync.Mutex
	connected bool
}

// NewSSHConnection creates a new SSH connection
func NewSSHConnection(config *SSHConfig) (*SSHConnection, error) {
	if config.Port == "" {
		config.Port = "22"
	}
	if config.User == "" {
		config.User = "root"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.BecomeMethod == "" && config.Become {
		config.BecomeMethod = "sudo"
	}
	if config.BecomeUser == "" && config.Become {
		config.BecomeUser = "root"
	}

	return &SSHConnection{
		Config: config,
	}, nil
}

// Connect establishes the SSH connection
func (s *SSHConnection) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connected && s.Client != nil {
		return nil
	}

	// Build auth methods
	var authMethods []ssh.AuthMethod

	// Try SSH key first
	if s.Config.KeyFile != "" {
		keyPath := expandPath(s.Config.KeyFile)
		if key, err := ioutil.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// Try default SSH keys if no key specified
	if s.Config.KeyFile == "" {
		homeDir, _ := os.UserHomeDir()
		defaultKeys := []string{
			filepath.Join(homeDir, ".ssh", "id_rsa"),
			filepath.Join(homeDir, ".ssh", "id_ed25519"),
			filepath.Join(homeDir, ".ssh", "id_ecdsa"),
		}
		for _, keyPath := range defaultKeys {
			if key, err := ioutil.ReadFile(keyPath); err == nil {
				if signer, err := ssh.ParsePrivateKey(key); err == nil {
					authMethods = append(authMethods, ssh.PublicKeys(signer))
					break
				}
			}
		}
	}

	// Add password authentication
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

	// Connect
	address := fmt.Sprintf("%s:%s", s.Config.Host, s.Config.Port)

	// Use a dialer with timeouts
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %v", address, err)
	}

	// Set TCP keepalive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake failed: %v", err)
	}

	s.Client = ssh.NewClient(sshConn, chans, reqs)
	s.connected = true

	return nil
}

// RunCommand executes a command via SSH
func (s *SSHConnection) RunCommand(name string, args ...string) (string, error) {
	return s.RunCommandWithTimeout(name, 60, args...)
}

// RunCommandWithTimeout executes a command via SSH with timeout
func (s *SSHConnection) RunCommandWithTimeout(name string, timeoutSecs int, args ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected || s.Client == nil {
		return "", fmt.Errorf("SSH connection not established")
	}

	// Create session
	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	// Build the command
	var cmdStr string

	// Handle special case of "bash -c" commands
	if name == "bash" && len(args) >= 2 && args[0] == "-c" {
		// This is already a bash command, just build it
		cmdStr = fmt.Sprintf("bash -c %s", shellQuote(args[1]))
	} else {
		// Build regular command
		cmdStr = name
		for _, arg := range args {
			cmdStr += " " + shellQuote(arg)
		}
	}

	// Apply privilege escalation if needed
	if s.Config.Become {
		cmdStr = s.wrapWithPrivilegeEscalation(cmdStr)
	}

	// Add timeout wrapper
	if timeoutSecs > 0 {
		cmdStr = fmt.Sprintf("timeout %d bash -c %s", timeoutSecs, shellQuote(cmdStr))
	}

	// Set up stdout and stderr
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// If using sudo with password, set up stdin
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		session.Stdin = strings.NewReader(s.Config.BecomePass + "\n")
	}

	// Execute the command
	err = session.Run(cmdStr)

	// Combine stdout and stderr
	output := stdout.String()
	if stderr.String() != "" {
		// Only append stderr if it's not a sudo password prompt
		stderrStr := stderr.String()
		if !strings.Contains(stderrStr, "password for") &&
			!strings.Contains(stderrStr, "[sudo]") {
			output += stderrStr
		}
	}

	// Clean output of sudo artifacts
	output = cleanSudoOutput(output)

	if err != nil {
		// Check if we got output despite error (some commands return non-zero but have valid output)
		if output != "" {
			return output, nil
		}
		return output, err
	}

	return output, nil
}

// wrapWithPrivilegeEscalation wraps a command with sudo/su
func (s *SSHConnection) wrapWithPrivilegeEscalation(cmd string) string {
	switch s.Config.BecomeMethod {
	case "su":
		if s.Config.BecomeUser != "" && s.Config.BecomeUser != "root" {
			return fmt.Sprintf("su - %s -c %s", s.Config.BecomeUser, shellQuote(cmd))
		}
		return fmt.Sprintf("su - -c %s", shellQuote(cmd))
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
		return fmt.Sprintf("%s bash -c %s", sudoCmd, shellQuote(cmd))
	default:
		return cmd
	}
}

// shellQuote quotes a string for safe shell execution
func shellQuote(s string) string {
	// If string contains no special characters, return as-is
	if !strings.ContainsAny(s, " \t\n'\"\\$`|&;<>(){}[]") {
		return s
	}
	// Use single quotes and escape existing single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// cleanSudoOutput removes sudo password prompts and other artifacts
func cleanSudoOutput(output string) string {
	lines := strings.Split(output, "\n")
	var cleaned []string

	for _, line := range lines {
		// Skip sudo password prompts and empty lines from sudo
		if strings.Contains(line, "[sudo]") ||
			strings.Contains(line, "password for") ||
			(strings.TrimSpace(line) == "" && len(cleaned) == 0) {
			continue
		}
		cleaned = append(cleaned, line)
	}

	return strings.Join(cleaned, "\n")
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
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

// IsConnected returns true if connected
func (s *SSHConnection) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}
