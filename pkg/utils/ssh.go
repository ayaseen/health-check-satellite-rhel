// pkg/utils/ssh.go

package utils

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	Config *SSHConfig
	Client *ssh.Client
}

// NewSSHConnection creates a new SSH connection
func NewSSHConnection(config *SSHConfig) (*SSHConnection, error) {
	return &SSHConnection{
		Config: config,
	}, nil
}

// Connect establishes the SSH connection
func (s *SSHConnection) Connect() error {
	var authMethods []ssh.AuthMethod

	// Add password authentication if password is provided
	if s.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.Config.Password))
	}

	// ALSO try SSH key authentication (not else if!)
	if s.Config.KeyFile != "" {
		keyAuth, err := s.getKeyAuth()
		if err == nil {
			authMethods = append(authMethods, keyAuth)
		}
		// Don't fail here, we might have password auth
	} else if s.Config.Password == "" {
		// Only if no password AND no explicit key file, try default locations
		defaultKeys := []string{
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"),
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"),
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_ecdsa"),
		}

		for _, keyPath := range defaultKeys {
			if fileExists(keyPath) {
				s.Config.KeyFile = keyPath
				keyAuth, err := s.getKeyAuth()
				if err == nil {
					authMethods = append(authMethods, keyAuth)
					break
				}
			}
		}
	}

	// Check if we have at least one auth method
	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication method available - please provide either SSH key or password")
	}

	// SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User:            s.Config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: In production, verify host key
		Timeout:         s.Config.Timeout,
		// Explicitly set to avoid any interactive prompts
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
		},
	}

	// Close existing connection if any
	if s.Client != nil {
		s.Client.Close()
		s.Client = nil
	}

	// Connect
	address := net.JoinHostPort(s.Config.Host, s.Config.Port)

	client, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	s.Client = client
	return nil
}

// getKeyAuth returns SSH key authentication method
func (s *SSHConnection) getKeyAuth() (ssh.AuthMethod, error) {
	// Expand path if it contains ~
	keyPath := s.Config.KeyFile
	if strings.HasPrefix(keyPath, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			keyPath = filepath.Join(home, keyPath[2:])
		}
	}

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key %s: %v", keyPath, err)
	}

	// Try parsing with no passphrase first
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// If it fails, it might need a passphrase
		// For now, we'll just return the error
		// In production, you'd want to handle passphrase-protected keys
		return nil, fmt.Errorf("unable to parse private key (it may be passphrase-protected): %v", err)
	}

	return ssh.PublicKeys(signer), nil
}

// RunCommand executes a command on the remote host
func (s *SSHConnection) RunCommand(name string, args ...string) (string, error) {
	if s.Client == nil {
		// Try to reconnect if client is nil
		if err := s.Connect(); err != nil {
			return "", fmt.Errorf("SSH client not connected and reconnection failed: %v", err)
		}
	}

	// Build the command
	cmd := s.buildCommand(name, args...)

	// Special handling for sudo with password
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		return s.runCommandWithSudoPassword(cmd)
	}

	// Regular command execution
	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Capture output
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run the command
	if err := session.Run(cmd); err != nil {
		// Include stderr in error message for debugging only if it's meaningful
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" && !strings.Contains(stderrStr, "password") && !strings.Contains(stderrStr, "sudo") {
			return stdout.String(), fmt.Errorf("command failed: %v (stderr: %s)", err, stderrStr)
		}
		// Return stdout even on error, as some commands exit non-zero but produce useful output
		if stdout.Len() > 0 {
			return stdout.String(), nil
		}
		return stdout.String(), fmt.Errorf("command failed: %v", err)
	}

	return stdout.String(), nil
}

// runCommandWithSudoPassword handles sudo commands that require a password
func (s *SSHConnection) runCommandWithSudoPassword(cmd string) (string, error) {
	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Set up pseudo terminal for sudo
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		// If PTY fails, try without it (some commands don't need it)
		return s.runCommandWithoutPty(cmd)
	}

	// Set up pipes
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start the command
	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}

	// Send password when prompted
	go func() {
		time.Sleep(100 * time.Millisecond) // Small delay to ensure sudo prompt appears
		io.WriteString(stdin, s.Config.BecomePass+"\n")
		stdin.Close()
	}()

	// Read output
	var outputBuf bytes.Buffer
	io.Copy(&outputBuf, stdout)

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		// Check if output contains useful data despite error
		output := outputBuf.String()
		// Remove sudo password prompt from output
		lines := strings.Split(output, "\n")
		var cleanLines []string
		for _, line := range lines {
			if !strings.Contains(line, "[sudo] password") &&
				!strings.Contains(line, "Password:") &&
				line != "" {
				cleanLines = append(cleanLines, line)
			}
		}
		cleanOutput := strings.Join(cleanLines, "\n")

		if cleanOutput != "" {
			return cleanOutput, nil // Return output even if there was an error code
		}
		return "", fmt.Errorf("command failed: %v", err)
	}

	// Clean the output from sudo prompts
	output := outputBuf.String()
	lines := strings.Split(output, "\n")
	var cleanLines []string
	for _, line := range lines {
		if !strings.Contains(line, "[sudo] password") &&
			!strings.Contains(line, "Password:") &&
			line != "" {
			cleanLines = append(cleanLines, line)
		}
	}

	return strings.Join(cleanLines, "\n"), nil
}

// runCommandWithoutPty runs command without pseudo terminal using echo pipe method
func (s *SSHConnection) runCommandWithoutPty(cmd string) (string, error) {
	// Use echo to pipe password to sudo -S
	// Escape single quotes in password
	escapedPass := strings.ReplaceAll(s.Config.BecomePass, "'", "'\\''")
	sudoCmd := fmt.Sprintf("echo '%s' | %s", escapedPass, cmd)

	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Capture output
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run the command
	if err := session.Run(sudoCmd); err != nil {
		// Check if we got output despite error
		if stdout.Len() > 0 {
			return stdout.String(), nil
		}
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" && !strings.Contains(stderrStr, "password") {
			return stdout.String(), fmt.Errorf("command failed: %v (stderr: %s)", err, stderrStr)
		}
		return stdout.String(), fmt.Errorf("command failed: %v", err)
	}

	return stdout.String(), nil
}

// RunCommandWithTimeout executes a command with a timeout
func (s *SSHConnection) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	if s.Client == nil {
		// Try to reconnect if client is nil
		if err := s.Connect(); err != nil {
			return "", fmt.Errorf("SSH client not connected and reconnection failed: %v", err)
		}
	}

	// Build the command with timeout wrapper
	baseCmd := s.buildCommand(name, args...)
	cmd := fmt.Sprintf("timeout %d %s", timeout, baseCmd)

	// Special handling for sudo with password
	if s.Config.Become && s.Config.BecomeMethod == "sudo" && s.Config.BecomePass != "" {
		return s.runCommandWithSudoPassword(cmd)
	}

	session, err := s.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Capture output
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run the command
	if err := session.Run(cmd); err != nil {
		// Check if it was a timeout
		if strings.Contains(stderr.String(), "timeout") || strings.Contains(err.Error(), "124") {
			return stdout.String(), fmt.Errorf("command timed out after %d seconds", timeout)
		}
		// Include stderr in error message for debugging
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" && !strings.Contains(stderrStr, "password") {
			return stdout.String(), fmt.Errorf("command failed: %v (stderr: %s)", err, stderrStr)
		}
		// Return stdout even on error
		if stdout.Len() > 0 {
			return stdout.String(), nil
		}
		return stdout.String(), fmt.Errorf("command failed: %v", err)
	}

	return stdout.String(), nil
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
				sudoCmd += " -S -p ''" // -S for stdin, -p '' for no prompt
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
	if s.Client != nil {
		return s.Client.Close()
	}
	return nil
}

// TestConnection tests if the SSH connection is working
func (s *SSHConnection) TestConnection() error {
	// For testing, temporarily disable privilege escalation
	oldBecome := s.Config.Become
	s.Config.Become = false

	output, err := s.RunCommand("echo", "test")

	// Restore privilege escalation setting
	s.Config.Become = oldBecome

	if err != nil {
		return err
	}
	if !strings.Contains(output, "test") {
		return fmt.Errorf("unexpected output from test command")
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
