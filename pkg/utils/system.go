// pkg/utils/system.go

package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// RunCommand runs a command using the current executor
// This uses the CommandExecutor from command_executor.go
func RunCommand(name string, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil {
		return executor.RunCommand(name, args...)
	}

	// Fallback to local execution if no executor set
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// RunCommandWithTimeout runs a command with timeout using the current executor
func RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil {
		return executor.RunCommandWithTimeout(name, timeout, args...)
	}

	// Fallback to local execution with timeout
	timeoutArgs := []string{fmt.Sprintf("%d", timeout), name}
	timeoutArgs = append(timeoutArgs, args...)
	cmd := exec.Command("timeout", timeoutArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// SafeRunCommand runs a command and returns a default value on error
// This is useful for avoiding null values in reports
func SafeRunCommand(defaultValue string, name string, args ...string) string {
	output, err := RunCommand(name, args...)
	if err != nil || strings.TrimSpace(output) == "" {
		return defaultValue
	}
	return strings.TrimSpace(output)
}

// GetRedHatVersion returns the major version of RHEL (e.g., "7", "8", "9")
func GetRedHatVersion() string {
	// Try to get from /etc/redhat-release
	output, err := RunCommand("bash", "-c", "cat /etc/redhat-release 2>/dev/null | grep -oE '[0-9]+' | head -1")
	if err == nil && output != "" {
		return strings.TrimSpace(output)
	}

	// Try rpm method
	output, err = RunCommand("bash", "-c", "rpm -E %{rhel} 2>/dev/null")
	if err == nil && output != "" && output != "%{rhel}" {
		return strings.TrimSpace(output)
	}

	// Default to 8
	return "8"
}

// RHELVersionInfo contains RHEL version details
type RHELVersionInfo struct {
	MajorVersion  string
	MinorVersion  string
	FullVersion   string
	ReleaseString string
	IsRHEL        bool
	IsCentOS      bool
	IsAlmaLinux   bool
	IsRockyLinux  bool
	IsOracleLinux bool
}

// GetRHELVersionInfo returns comprehensive RHEL version information
func GetRHELVersionInfo() RHELVersionInfo {
	info := RHELVersionInfo{
		MajorVersion: "Unknown",
		MinorVersion: "Unknown",
		FullVersion:  "Unknown",
		IsRHEL:       false,
	}

	// Get release info using bash for better remote compatibility
	releaseCmd := "cat /etc/redhat-release 2>/dev/null || cat /etc/system-release 2>/dev/null || echo ''"
	releaseContent, _ := RunCommand("bash", "-c", releaseCmd)
	releaseContent = strings.TrimSpace(releaseContent)

	if releaseContent != "" {
		info.ReleaseString = releaseContent

		// Check distribution type - ONLY RHEL matters for this tool
		if strings.Contains(releaseContent, "Red Hat Enterprise Linux") {
			info.IsRHEL = true
		}

		// Extract version
		versionCmd := "cat /etc/redhat-release 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+' | head -1"
		versionOutput, _ := RunCommand("bash", "-c", versionCmd)
		if versionOutput != "" {
			parts := strings.Split(strings.TrimSpace(versionOutput), ".")
			if len(parts) >= 1 {
				info.MajorVersion = parts[0]
				if len(parts) >= 2 {
					info.MinorVersion = parts[1]
				} else {
					info.MinorVersion = "0"
				}
				info.FullVersion = strings.TrimSpace(versionOutput)
			}
		}
	}

	// If still unknown, try os-release
	if info.MajorVersion == "Unknown" {
		osReleaseCmd := "grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '\"'"
		versionOutput, _ := RunCommand("bash", "-c", osReleaseCmd)
		if versionOutput != "" {
			parts := strings.Split(strings.TrimSpace(versionOutput), ".")
			if len(parts) >= 1 {
				info.MajorVersion = parts[0]
				if len(parts) >= 2 {
					info.MinorVersion = parts[1]
				} else {
					info.MinorVersion = "0"
				}
				info.FullVersion = strings.TrimSpace(versionOutput)
			}
		}

		// Check if it's RHEL from os-release
		idCmd := "grep '^ID=' /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '\"'"
		idOutput, _ := RunCommand("bash", "-c", idCmd)
		if strings.TrimSpace(idOutput) == "rhel" {
			info.IsRHEL = true
		}
	}

	// Last resort - try rpm
	if info.MajorVersion == "Unknown" {
		rpmCmd := "rpm -E %{rhel} 2>/dev/null"
		rpmOutput, _ := RunCommand("bash", "-c", rpmCmd)
		rpmOutput = strings.TrimSpace(rpmOutput)
		if rpmOutput != "" && rpmOutput != "%{rhel}" {
			info.MajorVersion = rpmOutput
			info.MinorVersion = "0"
			info.FullVersion = rpmOutput
			info.IsRHEL = true
		}
	}

	return info
}

// SystemInfo contains system information
type SystemInfo struct {
	Hostname     string
	FQDN         string
	Kernel       string
	Architecture string
	CPUInfo      string
	MemoryTotal  string
	SwapTotal    string
}

// GetSystemInfo collects comprehensive system information
func GetSystemInfo() SystemInfo {
	info := SystemInfo{
		Hostname:     "Unknown",
		FQDN:         "Unknown",
		Kernel:       "Unknown",
		Architecture: "Unknown",
		CPUInfo:      "Unknown",
		MemoryTotal:  "Unknown",
		SwapTotal:    "Unknown",
	}

	// Get hostname
	info.Hostname = SafeRunCommand("Unknown", "bash", "-c", "hostname 2>/dev/null")

	// Get FQDN
	info.FQDN = SafeRunCommand(info.Hostname, "bash", "-c", "hostname -f 2>/dev/null")

	// Get kernel
	info.Kernel = SafeRunCommand("Unknown", "bash", "-c", "uname -r 2>/dev/null")

	// Get architecture
	info.Architecture = SafeRunCommand("Unknown", "bash", "-c", "uname -m 2>/dev/null")

	// Get CPU info
	cpuCmd := "grep -c processor /proc/cpuinfo 2>/dev/null || echo '0'"
	cpuCount := SafeRunCommand("0", "bash", "-c", cpuCmd)
	info.CPUInfo = fmt.Sprintf("%s CPUs", cpuCount)

	// Get memory
	memCmd := "grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}'"
	memKB := SafeRunCommand("0", "bash", "-c", memCmd)
	info.MemoryTotal = fmt.Sprintf("%s KB", memKB)

	// Get swap
	swapCmd := "grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}'"
	swapKB := SafeRunCommand("0", "bash", "-c", swapCmd)
	info.SwapTotal = fmt.Sprintf("%s KB", swapKB)

	return info
}

// IsSatellite checks if the current system is a Satellite server
func IsSatellite() bool {
	// Check for satellite-installer
	output, _ := RunCommand("bash", "-c", "which satellite-installer 2>/dev/null")
	if output != "" {
		return true
	}

	// Check for satellite package
	output, _ = RunCommand("bash", "-c", "rpm -q satellite 2>/dev/null")
	if output != "" && !strings.Contains(output, "not installed") {
		return true
	}

	// Check for katello
	output, _ = RunCommand("bash", "-c", "rpm -q katello 2>/dev/null")
	if output != "" && !strings.Contains(output, "not installed") {
		return true
	}

	return false
}

// IsRoot checks if the current user is root
func IsRoot() bool {
	output, _ := RunCommand("bash", "-c", "id -u 2>/dev/null")
	return strings.TrimSpace(output) == "0"
}

// CreatePasswordProtectedZip creates a password-protected ZIP file
// Note: Go's archive/zip package doesn't support password protection natively
// This is a basic implementation - for production use, consider using external tools
func CreatePasswordProtectedZip(sourcePath, outputPath, password string) (string, error) {
	// For now, we'll create a regular zip without password
	// In production, you might want to use external tools like 7zip or use a third-party library

	// Create the ZIP file
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	// Create a new zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Open source file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	// Get file info
	fileInfo, err := sourceFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	// Create header
	header, err := zip.FileInfoHeader(fileInfo)
	if err != nil {
		return "", fmt.Errorf("failed to create file header: %v", err)
	}

	// Set compression
	header.Method = zip.Deflate

	// Note: Go's standard library doesn't support SetPassword
	// For password protection, you would need a third-party library like:
	// github.com/alexmullins/zip or use external tools

	// Create writer
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return "", fmt.Errorf("failed to create file in zip: %v", err)
	}

	// Copy content
	_, err = io.Copy(writer, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to write file to zip: %v", err)
	}

	// Note: This creates a regular ZIP without password protection
	// Consider using external tools for password protection:
	// cmd := exec.Command("zip", "-P", password, outputPath, sourcePath)

	return outputPath, nil
}
