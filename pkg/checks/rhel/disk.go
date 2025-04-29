// pkg/checks/rhel/disk.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunDiskChecks performs disk and filesystem related checks
func RunDiskChecks(r *report.AsciiDocReport) {
	// Check disk usage across all mounted filesystems
	checkDiskUsage(r)

	// Validate mount points and persistence
	checkMountPoints(r)

	// Confirm LVM, RAID, or multipath configuration
	checkStorageConfig(r)

	// Review I/O performance tuning
	checkIOPerformance(r)
}

// checkDiskUsage checks disk usage across all mounted filesystems
func checkDiskUsage(r *report.AsciiDocReport) {
	checkID := "disk-usage"
	checkName := "Disk Usage"
	checkDesc := "Checks disk usage across all mounted filesystems."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Get disk usage information
	dfCmd := "df -h"
	dfOutput, err := utils.RunCommand("bash", "-c", dfCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine disk usage", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'df' command is available.")
		r.AddCheck(check)
		return
	}

	// Get inode usage information
	dfInodeCmd := "df -i"
	dfInodeOutput, _ := utils.RunCommand("bash", "-c", dfInodeCmd)

	// Get list of large files
	largeFilesCmd := "find / -xdev -type f -size +100M -exec ls -lh {} \\; 2>/dev/null | sort -k5nr | head -10"
	largeFilesOutput, _ := utils.RunCommand("bash", "-c", largeFilesCmd)

	var detail strings.Builder
	detail.WriteString("Filesystem Disk Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(formatDfOutput(dfOutput))
	detail.WriteString("\n----\n\n")

	detail.WriteString("Filesystem Inode Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(formatDfOutput(dfInodeOutput))
	detail.WriteString("\n----\n\n")

	detail.WriteString("Largest Files (>100MB):\n")
	detail.WriteString("[source, bash]\n----\n")
	if largeFilesOutput == "" {
		detail.WriteString("No files larger than 100MB found or command timed out.\n")
	} else {
		detail.WriteString(formatLargeFilesOutput(largeFilesOutput))
	}
	detail.WriteString("\n----\n")

	// Parse df output to find high disk usage filesystems
	highUsageMountpoints := []string{}
	criticalUsageMountpoints := []string{}
	highInodeUsageMountpoints := []string{}

	// Check regular disk usage
	for _, line := range strings.Split(dfOutput, "\n") {
		if !strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "Filesystem") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		mountpoint := fields[5]
		usageStr := fields[4]

		// Skip certain temporary or pseudo filesystems
		if strings.HasPrefix(mountpoint, "/dev") ||
			strings.HasPrefix(mountpoint, "/proc") ||
			strings.HasPrefix(mountpoint, "/sys") ||
			strings.HasPrefix(mountpoint, "/run") {
			continue
		}

		// Parse usage percentage
		if len(usageStr) > 0 && strings.HasSuffix(usageStr, "%") {
			usageVal, err := strconv.Atoi(usageStr[:len(usageStr)-1])
			if err != nil {
				continue
			}

			if usageVal >= 90 {
				criticalUsageMountpoints = append(criticalUsageMountpoints,
					fmt.Sprintf("%s (%s)", mountpoint, usageStr))
			} else if usageVal >= 80 {
				highUsageMountpoints = append(highUsageMountpoints,
					fmt.Sprintf("%s (%s)", mountpoint, usageStr))
			}
		}
	}

	// Check inode usage
	for _, line := range strings.Split(dfInodeOutput, "\n") {
		if !strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "Filesystem") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		mountpoint := fields[5]
		usageStr := fields[4]

		// Skip certain temporary or pseudo filesystems
		if strings.HasPrefix(mountpoint, "/dev") ||
			strings.HasPrefix(mountpoint, "/proc") ||
			strings.HasPrefix(mountpoint, "/sys") ||
			strings.HasPrefix(mountpoint, "/run") {
			continue
		}

		// Parse usage percentage
		if len(usageStr) > 0 && strings.HasSuffix(usageStr, "%") {
			usageVal, err := strconv.Atoi(usageStr[:len(usageStr)-1])
			if err != nil {
				continue
			}

			if usageVal >= 80 {
				highInodeUsageMountpoints = append(highInodeUsageMountpoints,
					fmt.Sprintf("%s (%s inode usage)", mountpoint, usageStr))
			}
		}
	}

	// Evaluate disk usage
	if len(criticalUsageMountpoints) > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("Found %d filesystems with critical disk usage (≥90%%)", len(criticalUsageMountpoints)),
			report.ResultKeyRequired)

		for _, mp := range criticalUsageMountpoints {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Urgently free up space on %s", mp))
		}

		report.AddRecommendation(&check.Result, "Use 'du -sh /*' to identify large directories")
		report.AddRecommendation(&check.Result, "Consider removing old logs, temporary files, and package cache")

		// Add RHEL documentation reference directly as a link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-file-systems_managing-storage-devices", rhelVersion))
	} else if len(highUsageMountpoints) > 0 || len(highInodeUsageMountpoints) > 0 {
		allIssues := append(highUsageMountpoints, highInodeUsageMountpoints...)
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d filesystems with high usage (≥80%%)", len(allIssues)),
			report.ResultKeyRecommended)

		for _, mp := range highUsageMountpoints {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Monitor and plan to free space on %s", mp))
		}

		for _, mp := range highInodeUsageMountpoints {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Monitor high inode usage on %s", mp))
		}

		report.AddRecommendation(&check.Result, "For inode usage, look for directories with many small files")

		// Add RHEL documentation reference directly as a link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/file-system-checks-managing-storage-devices", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All filesystems have acceptable disk usage levels",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// formatDfOutput formats the output of df commands to make it more readable in the report
func formatDfOutput(output string) string {
	if output == "" {
		return "No data available"
	}

	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return output
	}

	// Process the header line
	header := lines[0]
	headerFields := strings.Fields(header)

	var result strings.Builder

	// Write the header
	for i, field := range headerFields {
		if i > 0 {
			result.WriteString("  ")
		}
		result.WriteString(field)
	}
	result.WriteString("\n")

	// Process data lines
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		fields := strings.Fields(lines[i])
		if len(fields) < 6 {
			result.WriteString(lines[i])
			result.WriteString("\n")
			continue
		}

		// Write each field with appropriate spacing
		for j, field := range fields {
			if j == 0 {
				// Filesystem field
				result.WriteString(field)
				result.WriteString("  ")
			} else if j < len(fields)-1 {
				// Middle fields
				result.WriteString(field)
				result.WriteString("    ")
			} else {
				// Last field (mount point)
				result.WriteString(field)
			}
		}
		result.WriteString("\n")
	}

	return result.String()
}

// formatLargeFilesOutput formats the output of large files command to make it more readable
func formatLargeFilesOutput(output string) string {
	if output == "" {
		return "No large files found"
	}

	lines := strings.Split(output, "\n")
	var result strings.Builder

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Format each line for better readability
		fields := strings.Fields(line)
		if len(fields) >= 9 { // Long format with date fields
			// Permissions
			result.WriteString(fields[0])
			result.WriteString("  ")

			// Links
			result.WriteString(fields[1])
			result.WriteString("  ")

			// Owner & Group
			result.WriteString(fields[2])
			result.WriteString("  ")
			result.WriteString(fields[3])
			result.WriteString("  ")

			// Size
			result.WriteString(fields[4])
			result.WriteString("  ")

			// Date (3 fields)
			result.WriteString(fields[5])
			result.WriteString(" ")
			result.WriteString(fields[6])
			result.WriteString(" ")
			result.WriteString(fields[7])
			result.WriteString("  ")

			// File path (remaining fields)
			for i := 8; i < len(fields); i++ {
				result.WriteString(fields[i])
				if i < len(fields)-1 {
					result.WriteString(" ")
				}
			}
		} else {
			// If we can't parse it properly, just use the original line
			result.WriteString(line)
		}
		result.WriteString("\n")
	}

	return result.String()
}

// checkMountPoints validates mount points and persistence
func checkMountPoints(r *report.AsciiDocReport) {
	checkID := "disk-mount-points"
	checkName := "Mount Points"
	checkDesc := "Validates mount points and persistence."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Get current mount information
	mountCmd := "mount"
	mountOutput, err := utils.RunCommand("bash", "-c", mountCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine mount points", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'mount' command is available.")
		r.AddCheck(check)
		return
	}

	// Get fstab entries
	fstabCmd := "cat /etc/fstab | grep -v '^#'"
	fstabOutput, _ := utils.RunCommand("bash", "-c", fstabCmd)

	// Check for mount option issues
	// Note: This variable was previously declared but not used
	// mountOptionIssues := []string{}

	// Get mount points with non-recommended options
	noatimeCmd := "mount | grep -v 'noatime' | grep -E '^/dev'"
	noatimeOutput, _ := utils.RunCommand("bash", "-c", noatimeCmd)

	// Check for non-persistent mounts
	mountedFSCmd := "mount | grep -E '^/dev' | awk '{print $1}'"
	mountedFSOutput, _ := utils.RunCommand("bash", "-c", mountedFSCmd)
	mountedFS := strings.Split(strings.TrimSpace(mountedFSOutput), "\n")

	fstabFSCmd := "cat /etc/fstab | grep -v '^#' | awk '{print $1}'"
	fstabFSOutput, _ := utils.RunCommand("bash", "-c", fstabFSCmd)
	fstabFS := strings.Split(strings.TrimSpace(fstabFSOutput), "\n")

	nonPersistentMounts := []string{}
	for _, fs := range mountedFS {
		if fs == "" {
			continue
		}

		persistent := false
		for _, fstabEntry := range fstabFS {
			if fs == fstabEntry ||
				(strings.HasPrefix(fs, "/dev/") && strings.HasPrefix(fstabEntry, "UUID=")) {
				persistent = true
				break
			}
		}

		if !persistent {
			mountInfoCmd := fmt.Sprintf("mount | grep '%s'", fs)
			mountInfo, _ := utils.RunCommand("bash", "-c", mountInfoCmd)
			nonPersistentMounts = append(nonPersistentMounts, mountInfo)
		}
	}

	var detail strings.Builder
	detail.WriteString("Current Mount Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(mountOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Mount Points in fstab:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fstabOutput)
	detail.WriteString("\n----\n")

	if len(nonPersistentMounts) > 0 {
		detail.WriteString("\n\nNon-Persistent Mounts:\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, mount := range nonPersistentMounts {
			detail.WriteString(mount + "\n")
		}
		detail.WriteString("\n----\n")
	}

	if noatimeOutput != "" {
		detail.WriteString("\n\nMount Points Without noatime Option:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(noatimeOutput)
		detail.WriteString("\n----\n")
	}

	// Evaluate mount points
	if len(nonPersistentMounts) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d non-persistent mounts", len(nonPersistentMounts)),
			report.ResultKeyRecommended)

		report.AddRecommendation(&check.Result, "Add the following mounts to /etc/fstab to make them persistent:")
		for _, mount := range nonPersistentMounts {
			report.AddRecommendation(&check.Result, fmt.Sprintf("- %s", mount))
		}

		report.AddRecommendation(&check.Result, "Use 'blkid' to get UUID values for more reliable mounting")

		// Add RHEL documentation reference directly as a link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/mounting-file-systems_managing-storage-devices", rhelVersion))
	} else if noatimeOutput != "" && len(nonPersistentMounts) == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Some mount points could be optimized with better options",
			report.ResultKeyAdvisory)

		report.AddRecommendation(&check.Result, "Consider adding 'noatime' mount option to improve performance")
		report.AddRecommendation(&check.Result, "Edit /etc/fstab and add 'noatime' to the options field (4th column)")

		// Add RHEL documentation reference directly as a link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/mounting-file-systems_managing-storage-devices#mount-options_mounting-file-systems", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All mount points are properly configured and persistent",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkStorageConfig confirms LVM, RAID, or multipath configuration
func checkStorageConfig(r *report.AsciiDocReport) {
	checkID := "storage-config"
	checkName := "Storage Configuration"
	checkDesc := "Confirms LVM, RAID, or multipath configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Check for LVM configuration
	lvmCmd := "lvs"
	lvmOutput, lvmErr := utils.RunCommand("bash", "-c", lvmCmd)

	vgCmd := "vgs"
	vgOutput, _ := utils.RunCommand("bash", "-c", vgCmd)

	pvCmd := "pvs"
	pvOutput, _ := utils.RunCommand("bash", "-c", pvCmd)

	// Check for RAID configuration
	raidCmd := "cat /proc/mdstat"
	raidOutput, _ := utils.RunCommand("bash", "-c", raidCmd)

	// Check for multipath configuration
	multipathCmd := "multipath -ll"
	multipathOutput, _ := utils.RunCommand("bash", "-c", multipathCmd)

	var detail strings.Builder
	detail.WriteString("LVM Configuration:\n\n")
	if lvmErr != nil {
		detail.WriteString("\nLVM not configured or lvs command not available\n")
	} else {
		detail.WriteString("\nLogical Volumes:\n\n")
		detail.WriteString("\n[source, bash]\n----\n")
		detail.WriteString(lvmOutput)
		detail.WriteString("\n----\n\n")
		detail.WriteString("Volume Groups:\n\n")
		detail.WriteString("\n[source, bash]\n----\n")
		detail.WriteString(vgOutput)
		detail.WriteString("\n----\n\n")
		detail.WriteString("Physical Volumes:\n\n")
		detail.WriteString("\n[source, bash]\n----\n")
		detail.WriteString(pvOutput)
		detail.WriteString("\n----\n")
	}

	detail.WriteString("\n\nRAID Configuration:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(raidOutput, "md") {
		detail.WriteString("\nNo software RAID configured\n")
	} else {
		detail.WriteString(raidOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multipath Configuration:\n")
	detail.WriteString("\n[source, bash]\n----\n")
	if strings.Contains(multipathOutput, "command not found") || strings.TrimSpace(multipathOutput) == "" {
		detail.WriteString("\nMultipath not configured or not installed\n")
	} else {
		detail.WriteString(multipathOutput)
	}
	detail.WriteString("\n----\n")

	// Determine storage configuration type
	hasLVM := !strings.Contains(lvmOutput, "No volume groups found") && lvmOutput != ""
	hasRAID := strings.Contains(raidOutput, "md")
	hasMultipath := !strings.Contains(multipathOutput, "command not found") && strings.TrimSpace(multipathOutput) != ""

	// Check for issues
	var issues []string

	if hasLVM {
		// Check for any issues with LVM configuration
		if strings.Contains(vgOutput, "WARNING") {
			issues = append(issues, "Warnings found in LVM volume groups")
		}
	}

	if hasRAID {
		// Check for degraded RAID arrays
		if strings.Contains(raidOutput, "degraded") {
			issues = append(issues, "Degraded RAID array detected")
		}
	}

	if hasMultipath {
		// Check for multipath issues
		if strings.Contains(multipathOutput, "failed") || strings.Contains(multipathOutput, "faulty") {
			issues = append(issues, "Issues detected in multipath configuration")
		}
	}

	// Evaluate storage configuration
	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d issues with storage configuration", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if strings.Contains(raidOutput, "degraded") {
			report.AddRecommendation(&check.Result, "Check RAID status with 'mdadm --detail /dev/mdX'")
			report.AddRecommendation(&check.Result, "Replace failed disks and rebuild array")

			// Add RHEL documentation reference directly as a link
			rhelVersion := utils.GetRedHatVersion()
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-software-raid_managing-storage-devices", rhelVersion))
		}

		if hasMultipath && (strings.Contains(multipathOutput, "failed") || strings.Contains(multipathOutput, "faulty")) {
			report.AddRecommendation(&check.Result, "Check multipath configuration with 'multipath -v3'")
			report.AddRecommendation(&check.Result, "Verify SAN connectivity and switch configuration")

			// Add RHEL documentation reference directly as a link
			rhelVersion := utils.GetRedHatVersion()
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/troubleshooting-multipathing_managing-storage-devices", rhelVersion))
		}
	} else {
		statusMsg := "Storage is properly configured"
		if hasLVM {
			statusMsg += " with LVM"
		}
		if hasRAID {
			if hasLVM {
				statusMsg += " and RAID"
			} else {
				statusMsg += " with RAID"
			}
		}
		if hasMultipath {
			if hasLVM || hasRAID {
				statusMsg += " and multipath"
			} else {
				statusMsg += " with multipath"
			}
		}

		check.Result = report.NewResult(report.StatusOK,
			statusMsg,
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkIOPerformance reviews I/O performance tuning
func checkIOPerformance(r *report.AsciiDocReport) {
	checkID := "disk-io-performance"
	checkName := "I/O Performance"
	checkDesc := "Reviews I/O performance tuning (scheduler, readahead, etc.)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get block device information
	blockDevCmd := "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT"
	blockDevOutput, err := utils.RunCommand("bash", "-c", blockDevCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine block device information", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'lsblk' command is available.")
		r.AddCheck(check)
		return
	}

	// Check RHEL version for appropriate scheduler recommendations
	rhelVersionCmd := "cat /etc/redhat-release | grep -oE '[0-9]+\\.[0-9]+' | cut -d. -f1"
	rhelVersionOutput, _ := utils.RunCommand("bash", "-c", rhelVersionCmd)
	rhelVersion, _ := strconv.Atoi(strings.TrimSpace(rhelVersionOutput))

	// Check if this is a virtual machine
	isVirtualCmd := "systemd-detect-virt 2>/dev/null || echo 'physical'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := strings.TrimSpace(isVirtualOutput) != "physical" && strings.TrimSpace(isVirtualOutput) != "Unknown"

	// Get I/O scheduler information for each block device
	var schedulerDetails strings.Builder
	schedulerDetails.WriteString("I/O Scheduler Settings:\n")

	// Extract device names
	var devices []string
	for _, line := range strings.Split(blockDevOutput, "\n") {
		if strings.Contains(line, "disk") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				devices = append(devices, fields[0])
			}
		}
	}

	// Check scheduler for each device
	var schedulerIssues []string
	for _, device := range devices {
		schedulerCmd := fmt.Sprintf("cat /sys/block/%s/queue/scheduler 2>/dev/null || echo 'Not available'", device)
		schedulerOutput, _ := utils.RunCommand("bash", "-c", schedulerCmd)
		schedulerOutput = strings.TrimSpace(schedulerOutput)

		// Check readahead value
		readaheadCmd := fmt.Sprintf("cat /sys/block/%s/queue/read_ahead_kb 2>/dev/null || echo 'Not available'", device)
		readaheadOutput, _ := utils.RunCommand("bash", "-c", readaheadCmd)
		readaheadOutput = strings.TrimSpace(readaheadOutput)

		schedulerDetails.WriteString(fmt.Sprintf("/dev/%s scheduler: %s, readahead: %s KB\n",
			device, schedulerOutput, readaheadOutput))

		// Check if this is an SSD
		rotationalCmd := fmt.Sprintf("cat /sys/block/%s/queue/rotational 2>/dev/null || echo 'Unknown'", device)
		rotationalOutput, _ := utils.RunCommand("bash", "-c", rotationalCmd)
		rotationalOutput = strings.TrimSpace(rotationalOutput)

		isSSD := rotationalOutput == "0"

		// Check if this is an NVMe device
		isNVMe := strings.HasPrefix(device, "nvme")

		// For RHEL 8+, use modern recommendations
		if rhelVersion >= 8 {
			// Extract active scheduler
			activeScheduler := ""
			if strings.Contains(schedulerOutput, "[") {
				start := strings.Index(schedulerOutput, "[") + 1
				end := strings.Index(schedulerOutput, "]")
				if start < end {
					activeScheduler = schedulerOutput[start:end]
				}
			}

			// For virtual disks in RHEL 8+
			if isVirtual {
				// For virtual guests, mq-deadline is the primary recommendation
				// But none is also acceptable with multi-queue capable HBA drivers
				if activeScheduler != "mq-deadline" && activeScheduler != "none" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is a virtual disk but doesn't use 'mq-deadline' or 'none' scheduler (recommended for RHEL 8+)", device))
				}
			} else if isNVMe {
				// For NVMe devices, none is specifically recommended
				if activeScheduler != "none" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is an NVMe device but doesn't use 'none' scheduler (recommended for RHEL 8+)", device))
				}
			} else if isSSD {
				// For high-performance SSDs, none is recommended, with kyber as alternative
				if activeScheduler != "none" && activeScheduler != "kyber" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is an SSD but doesn't use 'none' or 'kyber' scheduler (recommended for RHEL 8+)", device))
				}
			} else {
				// For traditional HDDs, mq-deadline or bfq are recommended
				if activeScheduler != "mq-deadline" && activeScheduler != "bfq" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is an HDD but doesn't use 'mq-deadline' or 'bfq' scheduler (recommended for RHEL 8+)", device))
				}
			}
		} else {
			// Pre-RHEL 8 recommendations
			if isSSD {
				// For SSDs, 'none' or 'noop' are typically best
				if !strings.Contains(schedulerOutput, "[none]") && !strings.Contains(schedulerOutput, "[noop]") {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is an SSD but doesn't use 'none' or 'noop' scheduler", device))
				}
			} else if !isSSD && rotationalOutput == "1" {
				if !strings.Contains(schedulerOutput, "[deadline]") && !strings.Contains(schedulerOutput, "[cfq]") {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("/dev/%s is an HDD but doesn't use 'deadline' or 'cfq' scheduler", device))
				}
			}
		}

		// Check readahead value - this is still relevant regardless of RHEL version
		readaheadVal, err := strconv.Atoi(readaheadOutput)
		if err == nil {
			if isSSD && readaheadVal > 512 {
				schedulerIssues = append(schedulerIssues,
					fmt.Sprintf("/dev/%s is an SSD with high readahead value (%d KB)", device, readaheadVal))
			} else if !isSSD && rotationalOutput == "1" && readaheadVal < 512 {
				schedulerIssues = append(schedulerIssues,
					fmt.Sprintf("/dev/%s is an HDD with low readahead value (%d KB)", device, readaheadVal))
			}
		}
	}

	// Get current I/O stats
	iostatCmd := "iostat -xtc 1 2 | tail -n +22"
	iostatOutput, _ := utils.RunCommand("bash", "-c", iostatCmd)

	var detail strings.Builder
	detail.WriteString("Block Device Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(blockDevOutput)
	detail.WriteString("\n----\n\n")
	detail.WriteString(schedulerDetails.String())
	detail.WriteString("\n\nI/O Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(iostatOutput)
	detail.WriteString("\n----\n")

	// Check for slow I/O
	ioIssues := []string{}

	// Look for high await times (>20ms is high, >50ms is very high)
	for _, line := range strings.Split(iostatOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 {
			// Check if this is a device line
			if strings.HasPrefix(fields[0], "sd") || strings.HasPrefix(fields[0], "nvme") {
				// 'await' field is typically in the 10th column (index 9)
				awaitStr := fields[9]
				await, err := strconv.ParseFloat(awaitStr, 64)
				if err == nil {
					if await > 50 {
						ioIssues = append(ioIssues,
							fmt.Sprintf("Very high I/O await time on %s: %.2f ms", fields[0], await))
					} else if await > 20 {
						ioIssues = append(ioIssues,
							fmt.Sprintf("High I/O await time on %s: %.2f ms", fields[0], await))
					}
				}
			}
		}
	}

	// Combine all issues
	allIssues := append(schedulerIssues, ioIssues...)

	// Evaluate I/O performance
	if len(allIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d I/O performance tuning issues", len(allIssues)),
			report.ResultKeyRecommended)

		for _, issue := range allIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if rhelVersion >= 8 {
			// RHEL 8+ recommendations based on official Red Hat documentation
			report.AddRecommendation(&check.Result, "For RHEL 8+:")
			report.AddRecommendation(&check.Result, "  - For virtual guests: use 'mq-deadline' scheduler (primary recommendation)")
			report.AddRecommendation(&check.Result, "    With a multi-queue capable HBA driver, 'none' is also suitable")
			report.AddRecommendation(&check.Result, "  - For NVMe devices: use 'none' scheduler (Red Hat specifically recommends not changing this)")
			report.AddRecommendation(&check.Result, "  - For high-performance SSDs: use 'none' or alternatively 'kyber'")
			report.AddRecommendation(&check.Result, "  - For traditional HDDs: use 'mq-deadline' or 'bfq'")
		} else {
			// Legacy RHEL recommendations
			report.AddRecommendation(&check.Result, "For SSDs, consider using 'none' or 'noop' scheduler")
			report.AddRecommendation(&check.Result, "For HDDs, consider using 'deadline' or 'cfq' scheduler")
		}

		report.AddRecommendation(&check.Result, "To set scheduler: echo scheduler_name > /sys/block/device/queue/scheduler")
		report.AddRecommendation(&check.Result, "To make changes persistent, add the appropriate udev rules")

		// Add RHEL documentation reference directly as a link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/setting-the-disk-scheduler_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"I/O performance tuning parameters are appropriately configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
