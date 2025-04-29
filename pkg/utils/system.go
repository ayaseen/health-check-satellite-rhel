// pkg/utils/system.go

package utils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alexmullins/zip"
)

// IsRHEL checks if the system is running RHEL
func IsRHEL() bool {
	// Check for the presence of /etc/redhat-release
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		// Read the file to confirm it's RHEL (not CentOS, Fedora, etc.)
		content, err := os.ReadFile("/etc/redhat-release")
		if err == nil {
			contentStr := strings.ToLower(string(content))
			return strings.Contains(contentStr, "red hat")
		}
	}

	// Secondary check via rpm
	cmd := exec.Command("rpm", "-q", "redhat-release")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// IsSatellite checks if the system is running Red Hat Satellite
func IsSatellite() bool {
	// Check for satellite-installer
	_, err := exec.LookPath("satellite-installer")
	if err == nil {
		return true
	}

	// Check for key Satellite packages
	satellitePackages := []string{"satellite", "katello", "foreman"}
	for _, pkg := range satellitePackages {
		cmd := exec.Command("rpm", "-q", pkg)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// Check for key Satellite services
	satelliteServices := []string{"foreman", "postgresql", "pulp"}
	for _, svc := range satelliteServices {
		cmd := exec.Command("systemctl", "status", svc)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	return false
}

// RunningAsRoot checks if the tool is running with root/sudo privileges
func RunningAsRoot() bool {
	return os.Geteuid() == 0
}

// RunCommand executes a command and returns its output
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command '%s %s' failed: %v", name, strings.Join(args, " "), err)
	}
	return string(output), nil
}

// RunCommandWithTimeout executes a command with a timeout
func RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	// Using context with timeout would be better, but for simplicity:
	timeoutArg := fmt.Sprintf("timeout %d %s %s", timeout, name, strings.Join(args, " "))

	cmd := exec.Command("bash", "-c", timeoutArg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "timed out") || strings.Contains(err.Error(), "exit status 124") {
			return string(output), fmt.Errorf("command timed out after %d seconds", timeout)
		}
		return string(output), fmt.Errorf("command '%s' failed: %v", timeoutArg, err)
	}
	return string(output), nil
}

// CompressWithPassword compresses a file with password protection
func CompressWithPassword(sourcePath string, password string) (string, error) {
	// Check if source exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return "", fmt.Errorf("source file not found: %s", sourcePath)
	}

	// Create zip file path
	zipPath := sourcePath + ".zip"

	// Create the zip file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	// Create zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Open source file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	// Get base filename
	baseFilename := filepath.Base(sourcePath)

	// Create encrypted entry
	writer, err := zipWriter.Encrypt(baseFilename, password)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypted entry: %v", err)
	}

	// Copy file content
	if _, err := io.Copy(writer, sourceFile); err != nil {
		return "", fmt.Errorf("failed to write to zip: %v", err)
	}

	return zipPath, nil
}

// GetRedHatVersion returns the major version of RHEL, defaulting to 8 for older versions
func GetRedHatVersion() string {
	rhelVersionCmd := "cat /etc/redhat-release 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+' | cut -d. -f1 || echo '8'"
	rhelVersionOutput, _ := RunCommand("bash", "-c", rhelVersionCmd)
	rhelVersion := strings.TrimSpace(rhelVersionOutput)
	if rhelVersion == "" || rhelVersion < "8" {
		rhelVersion = "8" // Default to RHEL 8 if detection fails or version is less than 8
	}
	return rhelVersion
}
