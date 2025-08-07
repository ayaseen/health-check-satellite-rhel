// pkg/utils/system.go

package utils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// IsRHEL checks if the current system is a Red Hat Enterprise Linux system
// This is the MISSING function that was causing compilation errors
func IsRHEL() bool {
	// Method 1: Check /etc/redhat-release
	releaseCmd := "cat /etc/redhat-release 2>/dev/null || cat /etc/system-release 2>/dev/null || echo ''"
	releaseContent, _ := RunCommand("bash", "-c", releaseCmd)
	if strings.Contains(releaseContent, "Red Hat Enterprise Linux") {
		return true
	}

	// Method 2: Check /etc/os-release
	idCmd := "grep '^ID=' /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '\"'"
	idOutput, _ := RunCommand("bash", "-c", idCmd)
	if strings.TrimSpace(idOutput) == "rhel" {
		return true
	}

	// Method 3: Check rpm database
	rpmCmd := "rpm -E %{rhel} 2>/dev/null"
	rpmOutput, _ := RunCommand("bash", "-c", rpmCmd)
	rpmOutput = strings.TrimSpace(rpmOutput)
	if rpmOutput != "" && rpmOutput != "%{rhel}" {
		// If rpm returns a number, it's RHEL
		return true
	}

	// Method 4: Check for redhat-release package
	pkgCmd := "rpm -q redhat-release 2>/dev/null"
	pkgOutput, _ := RunCommand("bash", "-c", pkgCmd)
	if pkgOutput != "" && !strings.Contains(pkgOutput, "not installed") {
		return true
	}

	return false
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

// CompressWithPassword creates a password-protected ZIP file
// This is the MISSING function that was causing compilation errors
func CompressWithPassword(sourcePath string, password string) (string, error) {
	// Generate output filename
	outputPath := sourcePath + ".zip"

	// Check if the 'zip' command is available
	checkZipCmd := "which zip 2>/dev/null"
	zipCheck, _ := RunCommand("bash", "-c", checkZipCmd)

	if zipCheck != "" {
		// Use system zip command for password protection
		zipCmd := fmt.Sprintf("zip -P '%s' '%s' '%s'", password, outputPath, sourcePath)
		output, err := RunCommand("bash", "-c", zipCmd)
		if err != nil {
			return "", fmt.Errorf("failed to compress with password: %v, output: %s", err, output)
		}
		return outputPath, nil
	}

	// Fallback to 7z if available
	check7zCmd := "which 7z 2>/dev/null"
	sevenZipCheck, _ := RunCommand("bash", "-c", check7zCmd)

	if sevenZipCheck != "" {
		// Use 7zip for password protection
		sevenZipCmd := fmt.Sprintf("7z a -p'%s' '%s' '%s'", password, outputPath, sourcePath)
		output, err := RunCommand("bash", "-c", sevenZipCmd)
		if err != nil {
			return "", fmt.Errorf("failed to compress with 7z: %v, output: %s", err, output)
		}
		return outputPath, nil
	}

	// If no password-capable compression tool is available,
	// create a regular zip without password and warn the user
	return CreatePasswordProtectedZip(sourcePath, outputPath, password)
}

// CreatePasswordProtectedZip creates a password-protected ZIP file using Go's archive/zip
// Note: Go's standard library doesn't support password protection natively
// This creates a regular ZIP and returns a warning
func CreatePasswordProtectedZip(sourcePath, outputPath, password string) (string, error) {
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
	header.Name = filepath.Base(sourcePath)

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
	// The password parameter is ignored in this implementation
	// For true password protection, install 'zip' or '7z' command-line tools

	fmt.Println("Warning: Created unencrypted ZIP file. Install 'zip' or '7z' for password protection.")

	return outputPath, nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetDiskUsage returns disk usage information for a given path
func GetDiskUsage(path string) (string, error) {
	cmd := fmt.Sprintf("df -h %s | tail -1", path)
	output, err := RunCommand("bash", "-c", cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// GetMemoryUsage returns current memory usage
func GetMemoryUsage() (string, error) {
	cmd := "free -h | grep '^Mem:' | awk '{print $3 \"/\" $2}'"
	output, err := RunCommand("bash", "-c", cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// GetLoadAverage returns system load average
func GetLoadAverage() (string, error) {
	output, err := RunCommand("bash", "-c", "uptime | awk -F'load average:' '{print $2}'")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// GetUptime returns system uptime
func GetUptime() (string, error) {
	output, err := RunCommand("bash", "-c", "uptime -p 2>/dev/null || uptime")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// GetServiceStatus checks if a service is running
func GetServiceStatus(serviceName string) (bool, string) {
	cmd := fmt.Sprintf("systemctl is-active %s 2>/dev/null", serviceName)
	output, _ := RunCommand("bash", "-c", cmd)
	status := strings.TrimSpace(output)
	return status == "active", status
}

// GetProcessCount returns the number of running processes
func GetProcessCount() (int, error) {
	output, err := RunCommand("bash", "-c", "ps aux | wc -l")
	if err != nil {
		return 0, err
	}

	count := 0
	fmt.Sscanf(strings.TrimSpace(output), "%d", &count)
	return count, nil
}

// GetKernelParameters returns kernel boot parameters
func GetKernelParameters() (string, error) {
	output, err := RunCommand("bash", "-c", "cat /proc/cmdline")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// GetSELinuxStatus returns SELinux status
func GetSELinuxStatus() (string, error) {
	output, err := RunCommand("bash", "-c", "getenforce 2>/dev/null || echo 'Not installed'")
	if err != nil {
		return "Unknown", err
	}
	return strings.TrimSpace(output), nil
}

// GetFirewallStatus returns firewall status
func GetFirewallStatus() (string, error) {
	// Try firewalld first
	output, err := RunCommand("bash", "-c", "systemctl is-active firewalld 2>/dev/null")
	if err == nil && strings.TrimSpace(output) == "active" {
		return "firewalld: active", nil
	}

	// Try iptables
	output, err = RunCommand("bash", "-c", "systemctl is-active iptables 2>/dev/null")
	if err == nil && strings.TrimSpace(output) == "active" {
		return "iptables: active", nil
	}

	return "No firewall active", nil
}
