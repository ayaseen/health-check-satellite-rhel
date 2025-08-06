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

	// Determine authentication method
	if s.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.Config.Password))
	} else if s.Config.KeyFile != "" {
		keyAuth, err := s.getKeyAuth()
		if err == nil {
			authMethods = append(authMethods, keyAuth)
		} else {
			return fmt.Errorf("failed to load SSH key from %s: %v", s.Config.KeyFile, err)
		}
	} else {
		// Try default key
		defaultKeyPath := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")
		if fileExists(defaultKeyPath) {
			s.Config.KeyFile = defaultKeyPath
			keyAuth, err := s.getKeyAuth()
			if err == nil {
				authMethods = append(authMethods, keyAuth)
			} else {
				return fmt.Errorf("no authentication method available - please provide either SSH key or password")
			}
		} else {
			return fmt.Errorf("no authentication method available - no password provided and no SSH key found")
		}
	}

	// SSH client configuration with no keyboard-interactive to avoid prompts
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
	key, err := ioutil.ReadFile(s.Config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
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

	session, err := s.Client.NewSession()
	if err != nil {
		// If session creation fails, it might be because the connection is dead
		// Try to reconnect once
		if err := s.Connect(); err != nil {
			return "", fmt.Errorf("failed to create session and reconnection failed: %v", err)
		}

		// Try creating session again
		session, err = s.Client.NewSession()
		if err != nil {
			return "", fmt.Errorf("failed to create session after reconnection: %v", err)
		}
	}
	defer session.Close()

	// Build the command
	var cmdBuilder strings.Builder
	cmdBuilder.WriteString(name)
	for _, arg := range args {
		cmdBuilder.WriteString(" ")
		// Quote arguments that contain spaces
		if strings.Contains(arg, " ") {
			cmdBuilder.WriteString("\"")
			cmdBuilder.WriteString(arg)
			cmdBuilder.WriteString("\"")
		} else {
			cmdBuilder.WriteString(arg)
		}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Run(cmdBuilder.String())

	output := stdoutBuf.String() + stderrBuf.String()

	if err != nil {
		// Don't treat all errors as fatal - some commands may legitimately fail
		return output, nil
	}

	return output, nil
}

// RunCommandWithTimeout executes a command with timeout
func (s *SSHConnection) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	// For remote execution, prepend timeout command
	timeoutArgs := []string{fmt.Sprintf("%d", timeout), name}
	timeoutArgs = append(timeoutArgs, args...)
	return s.RunCommand("timeout", timeoutArgs...)
}

// Close closes the SSH connection
func (s *SSHConnection) Close() error {
	if s.Client != nil {
		return s.Client.Close()
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
