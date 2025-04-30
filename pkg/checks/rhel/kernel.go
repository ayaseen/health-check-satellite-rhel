// pkg/checks/rhel/kernel.go

package rhel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunKernelChecks performs kernel related checks
func RunKernelChecks(r *report.AsciiDocReport) {
	// Confirm kernel and microcode versions are updated
	checkKernelVersion(r)

	// Validate BIOS/UEFI firmware versions
	checkFirmwareVersion(r)

	// Disable unused onboard devices
	checkUnusedDevices(r)
}

// extractKernelBase extracts the base kernel version without architecture suffix
func extractKernelBase(kernelVersion string) string {
	// Remove architecture suffix if present
	if idx := strings.LastIndex(kernelVersion, "."); idx != -1 {
		if arch := kernelVersion[idx+1:]; arch == "x86_64" || arch == "aarch64" || arch == "ppc64le" || arch == "s390x" {
			// If it's a known architecture, remove it for comparison
			return kernelVersion[:idx]
		}
	}

	// Handle potential other formats - look for known patterns
	kernelPattern := regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+\.\d+\.\d+\.el\d+(?:_\d+)?)`)
	if match := kernelPattern.FindStringSubmatch(kernelVersion); len(match) > 1 {
		return match[1]
	}

	// If no specific pattern matches, return as is
	return kernelVersion
}

// extractVersionNumbers extracts version numbers from a kernel version string
func extractVersionNumbers(version string) []int {
	var numbers []int

	// Split on both dots and hyphens
	parts := strings.FieldsFunc(version, func(r rune) bool {
		return r == '.' || r == '-'
	})

	for _, part := range parts {
		// Extract only the numeric part at the beginning of the string
		numStr := ""
		for _, char := range part {
			if char >= '0' && char <= '9' {
				numStr += string(char)
			} else {
				break
			}
		}

		if numStr != "" {
			num, err := strconv.Atoi(numStr)
			if err == nil {
				numbers = append(numbers, num)
			}
		}
	}

	return numbers
}

// compareVersions compares two version number arrays
func compareVersions(a, b []int) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	// Compare common parts
	for i := 0; i < minLen; i++ {
		if a[i] > b[i] {
			return 1
		} else if a[i] < b[i] {
			return -1
		}
	}

	// If common parts are equal, longer version is newer
	if len(a) > len(b) {
		return 1
	} else if len(a) < len(b) {
		return -1
	}

	return 0 // Versions are equal
}

// checkKernelVersion confirms kernel and microcode versions are updated
func checkKernelVersion(r *report.AsciiDocReport) {
	checkID := "kernel-version"
	checkName := "Kernel Version"
	checkDesc := "Confirms kernel and microcode versions are updated."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Get current kernel with full version - this is the running kernel
	currentKernelCmd := "uname -r"
	currentKernelOutput, _ := utils.RunCommand("bash", "-c", currentKernelCmd)
	currentKernel := strings.TrimSpace(currentKernelOutput)

	// Get latest available kernel from repositories - using grep to filter out any messages
	latestAvailableCmd := "dnf repoquery --latest-limit 1 kernel 2>/dev/null | grep -o 'kernel-[0-9].*' || echo 'Unable to query latest'"
	latestAvailableOutput, _ := utils.RunCommand("bash", "-c", latestAvailableCmd)
	latestAvailable := strings.TrimSpace(latestAvailableOutput)

	// Format the latest available kernel for comparison
	formattedLatestAvailable := latestAvailable
	formattedLatestAvailable = strings.TrimPrefix(formattedLatestAvailable, "kernel-0:")
	formattedLatestAvailable = strings.TrimPrefix(formattedLatestAvailable, "kernel-")

	// Check repository metadata age to detect stale repositories
	repoMetaAgeCmd := "find /var/cache/dnf -type f -path '*/repodata/repomd.xml' -exec stat -c '%Y' {} \\; 2>/dev/null | sort -nr | head -n1 || echo '0'"
	repoMetaAgeOutput, _ := utils.RunCommand("bash", "-c", repoMetaAgeCmd)
	repoMetaAge := strings.TrimSpace(repoMetaAgeOutput)

	// Calculate repository metadata age in days
	repoMetaTimestamp, err := strconv.ParseInt(repoMetaAge, 10, 64)
	if err != nil {
		repoMetaTimestamp = 0
	}
	now := time.Now().Unix()
	metaAgeDays := (now - repoMetaTimestamp) / 86400

	// Simple direct comparison - is running kernel the latest available?
	staleMetadata := metaAgeDays > 7 // Consider metadata stale if older than 7 days
	runningLatest := currentKernel == formattedLatestAvailable

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	repoDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Current Running Kernel:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(currentKernel)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Latest Available Kernel:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(latestAvailable)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Repository Metadata Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	if repoMetaTimestamp > 0 {
		metaDate := time.Unix(repoMetaTimestamp, 0).Format("2006-01-02 15:04:05")
		detail.WriteString(fmt.Sprintf("Metadata last updated: %s (%d days ago)\n", metaDate, metaAgeDays))
	} else {
		detail.WriteString("Could not determine repository metadata age\n")
	}
	detail.WriteString("\n----\n\n")

	// Add kernel status summary
	detail.WriteString("Kernel Version Status Summary:\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(fmt.Sprintf("Running kernel: %s\n", currentKernel))
	detail.WriteString(fmt.Sprintf("Latest available kernel: %s\n", latestAvailable))
	detail.WriteString(fmt.Sprintf("Formatted for comparison: %s\n", formattedLatestAvailable))
	detail.WriteString(fmt.Sprintf("Repository metadata age: %d days\n", metaAgeDays))
	detail.WriteString(fmt.Sprintf("Running latest kernel: %v\n", runningLatest))
	detail.WriteString("\n----\n\n")

	// Evaluate results
	if staleMetadata {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Repository metadata is %d days old - unable to reliably determine if latest kernel is installed", metaAgeDays),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Refresh repository metadata with 'subscription-manager refresh'")
		report.AddRecommendation(&check.Result, "For disconnected environments, sync content from Satellite server")
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sindex", repoDocURL))
	} else if !runningLatest && strings.Contains(latestAvailable, "Unable to query") {
		check.Result = report.NewResult(report.StatusWarning,
			"Unable to determine latest available kernel",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check repository configuration and connectivity")
		report.AddRecommendation(&check.Result, "For systems managed via Satellite, verify content views are properly synced")
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%stroubleshooting_problems_with_packages_repositories_and_files", repoDocURL))
	} else if !runningLatest {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("System is not running the latest available kernel (running: %s, latest: %s)",
				currentKernel, formattedLatestAvailable),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Update kernel with 'yum update kernel' and reboot")
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%supdating-packages", repoDocURL))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System is running the latest available kernel",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFirmwareVersion validates BIOS/UEFI firmware versions
func checkFirmwareVersion(r *report.AsciiDocReport) {
	checkID := "kernel-firmware"
	checkName := "BIOS/UEFI Firmware"
	checkDesc := "Validates BIOS/UEFI firmware versions."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Get firmware information using dmidecode
	firmwareCmd := "dmidecode -t bios 2>/dev/null || echo 'dmidecode not available'"
	firmwareOutput, _ := utils.RunCommand("bash", "-c", firmwareCmd)

	// Get system information
	systemInfoCmd := "dmidecode -t system 2>/dev/null || echo 'dmidecode not available'"
	systemInfoOutput, _ := utils.RunCommand("bash", "-c", systemInfoCmd)

	// Check specific firmware vulnerabilities (speculative)
	intelMDS := "cat /sys/devices/system/cpu/vulnerabilities/mds 2>/dev/null || echo 'Not available'"
	intelMDSOutput, _ := utils.RunCommand("bash", "-c", intelMDS)

	// Check if system is virtual
	isVirtualCmd := "systemd-detect-virt 2>/dev/null || echo 'Unknown'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := strings.TrimSpace(isVirtualOutput) != "Unknown" && strings.TrimSpace(isVirtualOutput) != "none"

	// Get firmware date and version if available
	firmwareDate := "Unknown"
	firmwareVersion := "Unknown"
	firmwareVendor := "Unknown"

	for _, line := range strings.Split(firmwareOutput, "\n") {
		if strings.Contains(line, "Release Date:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				firmwareDate = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Version:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				firmwareVersion = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Vendor:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				firmwareVendor = strings.TrimSpace(parts[1])
			}
		}
	}

	// Get system manufacturer and model
	systemManufacturer := "Unknown"
	systemModel := "Unknown"

	for _, line := range strings.Split(systemInfoOutput, "\n") {
		if strings.Contains(line, "Manufacturer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				systemManufacturer = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Product Name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				systemModel = strings.TrimSpace(parts[1])
			}
		}
	}

	// Get RHEL version for documentation
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("System Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("System Manufacturer: %s\n", systemManufacturer))
	detail.WriteString(fmt.Sprintf("System Model: %s\n", systemModel))
	detail.WriteString(fmt.Sprintf("Firmware Vendor: %s\n", firmwareVendor))
	detail.WriteString(fmt.Sprintf("Firmware Version: %s\n", firmwareVersion))
	detail.WriteString(fmt.Sprintf("Firmware Date: %s\n", firmwareDate))
	detail.WriteString(fmt.Sprintf("System Type: %s\n", isVirtualOutput))
	detail.WriteString("\n----\n\n")

	detail.WriteString("Firmware Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(firmwareOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("System Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(systemInfoOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Intel MDS Vulnerability Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(intelMDSOutput)
	detail.WriteString("\n----\n")

	// Get documentation URLs based on RHEL version

	virtDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/#Virtualization", rhelVersion)
	hwDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/#Planning", rhelVersion)
	vulnDocURL := "https://access.redhat.com/security/vulnerabilities/mds"

	// Evaluate firmware version
	if isVirtual {
		check.Result = report.NewResult(report.StatusInfo,
			"This is a virtual machine - firmware is managed by the hypervisor",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Ensure the hypervisor host's firmware is up to date")
		report.AddReferenceLink(&check.Result, virtDocURL)
	} else if firmwareVersion == "Unknown" || firmwareDate == "Unknown" {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine firmware version information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check firmware version in system BIOS/UEFI setup")
		report.AddRecommendation(&check.Result, "Ensure 'dmidecode' is installed for firmware information")
		report.AddReferenceLink(&check.Result, hwDocURL)
	} else if strings.Contains(intelMDSOutput, "Vulnerable") && !strings.Contains(intelMDSOutput, "Not affected") {
		check.Result = report.NewResult(report.StatusWarning,
			"System may be vulnerable to CPU issues that require firmware updates",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Check for firmware updates for %s %s", systemManufacturer, systemModel))
		report.AddRecommendation(&check.Result, "Apply latest firmware updates to address CPU vulnerabilities")
		report.AddReferenceLink(&check.Result, vulnDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Firmware information: %s version %s (%s)", firmwareVendor, firmwareVersion, firmwareDate),
			report.ResultKeyNoChange)
		report.AddRecommendation(&check.Result, "Periodically check for firmware updates from the system manufacturer")
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkUnusedDevices verifies that unused onboard devices are disabled
func checkUnusedDevices(r *report.AsciiDocReport) {
	checkID := "kernel-unused-devices"
	checkName := "Unused Devices"
	checkDesc := "Verifies that unused onboard devices are disabled."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check for commonly unnecessary devices
	deviceStatusCmd := "lspci -k"
	deviceStatusOutput, _ := utils.RunCommand("bash", "-c", deviceStatusCmd)

	// Check for blacklisted modules
	blacklistCmd := "find /etc/modprobe.d -name '*.conf' -exec grep -l 'blacklist' {} \\; | xargs cat 2>/dev/null || echo 'No blacklisted modules found'"
	blacklistOutput, _ := utils.RunCommand("bash", "-c", blacklistCmd)

	// Get boot parameters for disabled modules
	bootParamsCmd := "grep -E 'module\\.blacklist|modprobe\\.blacklist' /proc/cmdline || echo 'No module blacklisting in kernel parameters'"
	bootParamsOutput, _ := utils.RunCommand("bash", "-c", bootParamsCmd)

	// Check for common unused devices and their status
	unusedDevices := []string{
		"bluetooth", "firewire", "thunderbolt", "wireless",
		"sound", "webcam", "smartcard", "fingerprint",
	}

	var deviceStatus = make(map[string]bool)
	var loadedUnusedModules []string

	// Check if any potentially unused devices are loaded
	for _, device := range unusedDevices {
		deviceStatus[device] = false

		deviceDetectionCmd := ""
		switch device {
		case "bluetooth":
			deviceDetectionCmd = "lsmod | grep -E '(bluetooth|btusb)' || echo 'not loaded'"
		case "firewire":
			deviceDetectionCmd = "lsmod | grep -E '(firewire|ohci1394)' || echo 'not loaded'"
		case "thunderbolt":
			deviceDetectionCmd = "lsmod | grep -E '(thunderbolt)' || echo 'not loaded'"
		case "wireless":
			deviceDetectionCmd = "lsmod | grep -E '(iwlwifi|ath|rtl|wl)' || echo 'not loaded'"
		case "sound":
			deviceDetectionCmd = "lsmod | grep -E '(snd|sound)' || echo 'not loaded'"
		case "webcam":
			deviceDetectionCmd = "lsmod | grep -E '(uvcvideo|gspca)' || echo 'not loaded'"
		case "smartcard":
			deviceDetectionCmd = "lsmod | grep -E '(pn533|nfc)' || echo 'not loaded'"
		case "fingerprint":
			deviceDetectionCmd = "lsmod | grep -E '(usbhid|fprintd)' || echo 'not loaded'"
		}

		if deviceDetectionCmd != "" {
			deviceOutput, _ := utils.RunCommand("bash", "-c", deviceDetectionCmd)
			if !strings.Contains(deviceOutput, "not loaded") {
				deviceStatus[device] = true
				loadedUnusedModules = append(loadedUnusedModules, device)
			}
		}
	}

	// Get RHEL version for documentation
	rhelVersion := utils.GetRedHatVersion()
	kernelModuleDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/managing_monitoring_and_updating_the_kernel/index", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Device Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	for device, loaded := range deviceStatus {
		if loaded {
			detail.WriteString(fmt.Sprintf("- %s: Loaded\n", device))
		} else {
			detail.WriteString(fmt.Sprintf("- %s: Not loaded\n", device))
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kernel Module Blacklisting:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(blacklistOutput, "No blacklisted modules found") {
		detail.WriteString("No modules blacklisted in /etc/modprobe.d/\n")
	} else {
		detail.WriteString(blacklistOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kernel Boot Parameters for Blacklisting:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(bootParamsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("PCI Devices and Drivers:\n")
	detail.WriteString("[source, bash]\n----\n")
	// Trim the output if it's too long
	if len(deviceStatusOutput) > 1500 {
		lines := strings.Split(deviceStatusOutput, "\n")
		if len(lines) > 20 {
			detail.WriteString(strings.Join(lines[:20], "\n"))
			detail.WriteString("\n... (output truncated)\n")
		} else {
			detail.WriteString(deviceStatusOutput)
		}
	} else {
		detail.WriteString(deviceStatusOutput)
	}
	detail.WriteString("\n----\n")

	// Check if this is a virtual machine
	isVirtualCmd := "systemd-detect-virt 2>/dev/null || echo 'physical'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := strings.TrimSpace(isVirtualOutput) != "physical" && strings.TrimSpace(isVirtualOutput) != "Unknown"

	// Determine which devices should be disabled in a server environment
	// In server environments, typically audio, bluetooth, wireless, webcam etc. should be disabled
	serverUnnecessaryDevices := []string{"bluetooth", "firewire", "wireless", "sound", "webcam"}

	var activeServerUnnecessaryDevices []string
	for _, device := range serverUnnecessaryDevices {
		if deviceStatus[device] {
			activeServerUnnecessaryDevices = append(activeServerUnnecessaryDevices, device)
		}
	}

	// Evaluate device status
	if isVirtual {
		check.Result = report.NewResult(report.StatusInfo,
			"This is a virtual machine - device management is handled by the hypervisor",
			report.ResultKeyNotApplicable)
	} else if len(activeServerUnnecessaryDevices) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d active devices that are often unnecessary in servers", len(activeServerUnnecessaryDevices)),
			report.ResultKeyRecommended)

		for _, device := range activeServerUnnecessaryDevices {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Consider disabling %s if not needed", device))
		}

		report.AddRecommendation(&check.Result, "Disable unused devices by blacklisting their kernel modules")
		report.AddRecommendation(&check.Result, "For example: echo 'blacklist bluetooth' > /etc/modprobe.d/blacklist-bluetooth.conf")
		report.AddReferenceLink(&check.Result, kernelModuleDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No unnecessary devices detected or they are properly disabled",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
