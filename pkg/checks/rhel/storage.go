// pkg/checks/rhel/storage.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunStorageChecks performs storage related checks
func RunStorageChecks(r *report.AsciiDocReport) {
	// Validate multipath configuration
	checkMultipathConfig(r)

	// Confirm filesystem type compatibility
	checkFilesystemTypes(r)

	// Ensure no filesystem errors
	checkFilesystemErrors(r)

	// Check partition alignment
	checkPartitionAlignment(r)
}

// checkMultipathConfig validates multipath configuration
func checkMultipathConfig(r *report.AsciiDocReport) {
	checkID := "storage-multipath"
	checkName := "Multipath Configuration"
	checkDesc := "Validates multipath configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Check if multipath is installed
	multipathCmd := "rpm -q device-mapper-multipath || echo 'Multipath not installed'"
	multipathOutput, _ := utils.RunCommand("bash", "-c", multipathCmd)
	multipathInstalled := !strings.Contains(multipathOutput, "not installed")

	if !multipathInstalled {
		check.Result = report.NewResult(report.StatusInfo,
			"Multipath is not installed",
			report.ResultKeyNotApplicable)
		report.AddRecommendation(&check.Result, "This check is not applicable as device-mapper-multipath is not installed")
		r.AddCheck(check)
		return
	}

	// Check multipath configuration
	multipathConfCmd := "cat /etc/multipath.conf 2>/dev/null || echo 'No multipath configuration file found'"
	multipathConfOutput, _ := utils.RunCommand("bash", "-c", multipathConfCmd)

	// Check if multipath service is running
	multipathStatusCmd := "systemctl status multipathd 2>/dev/null | grep 'Active:' || echo 'Multipath service not found'"
	multipathStatusOutput, _ := utils.RunCommand("bash", "-c", multipathStatusCmd)
	multipathActive := strings.Contains(multipathStatusOutput, "active (running)")

	// Check multipath devices
	multipathDevicesCmd := "multipath -ll 2>/dev/null || echo 'No multipath devices found'"
	multipathDevicesOutput, _ := utils.RunCommand("bash", "-c", multipathDevicesCmd)
	hasMultipathDevices := !strings.Contains(multipathDevicesOutput, "No multipath devices found")

	// Check for errors in multipath
	multipathErrorsCmd := "dmesg | grep -i multipath | grep -i error || echo 'No multipath errors found in logs'"
	multipathErrorsOutput, _ := utils.RunCommand("bash", "-c", multipathErrorsCmd)
	hasMultipathErrors := !strings.Contains(multipathErrorsOutput, "No multipath errors found in logs")

	var detail strings.Builder
	detail.WriteString("Multipath Package:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(multipathOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multipath Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(multipathStatusOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multipath Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(multipathConfOutput, "No multipath configuration file found") {
		// Show a condensed version of the config
		inSection := false
		for _, line := range strings.Split(multipathConfOutput, "\n") {
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "#") {
				continue
			}

			if strings.Contains(trimmedLine, "{") {
				inSection = true
				detail.WriteString(line + "\n")
			} else if strings.Contains(trimmedLine, "}") {
				inSection = false
				detail.WriteString(line + "\n")
			} else if inSection && trimmedLine != "" {
				detail.WriteString(line + "\n")
			} else if strings.Contains(trimmedLine, "defaults") ||
				strings.Contains(trimmedLine, "blacklist") ||
				strings.Contains(trimmedLine, "devices") {
				detail.WriteString(line + "\n")
			}
		}
	} else {
		detail.WriteString(multipathConfOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multipath Devices:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasMultipathDevices {
		detail.WriteString(multipathDevicesOutput)
	} else {
		detail.WriteString("No multipath devices found\n")
	}
	detail.WriteString("\n----\n")

	if hasMultipathErrors {
		detail.WriteString("\nMultipath Errors:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(multipathErrorsOutput)
		detail.WriteString("\n----\n")
	}

	// Evaluate multipath configuration
	if !multipathActive {
		check.Result = report.NewResult(report.StatusWarning,
			"Multipath is installed but not running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start multipath service: 'systemctl start multipathd'")
		report.AddRecommendation(&check.Result, "Enable multipath service: 'systemctl enable multipathd'")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/configuring-device-mapper-multipath_managing-storage-devices", rhelVersion))
	} else if strings.Contains(multipathConfOutput, "No multipath configuration file found") {
		check.Result = report.NewResult(report.StatusWarning,
			"Multipath is running but no configuration file found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create a multipath configuration file: '/etc/multipath.conf'")
		report.AddRecommendation(&check.Result, "Generate default config: 'mpathconf --enable --with_multipathd y'")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/setting-up-multipathing_managing-storage-devices", rhelVersion, rhelVersion))
	} else if hasMultipathErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Multipath errors detected in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review multipath errors and check SAN connectivity")
		report.AddRecommendation(&check.Result, "Verify multipath configuration is appropriate for your storage")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/troubleshooting-multipathing_managing-storage-devices", rhelVersion))
	} else if hasMultipathDevices {
		check.Result = report.NewResult(report.StatusOK,
			"Multipath is properly configured and active with devices",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusInfo,
			"Multipath is properly configured but no devices detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify SAN connectivity if multipath devices are expected")
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFilesystemTypes confirms filesystem type compatibility
func checkFilesystemTypes(r *report.AsciiDocReport) {
	checkID := "storage-filesystem-types"
	checkName := "Filesystem Types"
	checkDesc := "Confirms filesystem type compatibility."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Get mounted filesystems
	mountedFSCmd := "mount | grep -v tmpfs | grep -v cgroup | grep -v proc | grep -v sysfs | grep -v devpts"
	mountedFSOutput, _ := utils.RunCommand("bash", "-c", mountedFSCmd)

	// Check filesystem types in use
	fsTypesCmd := "df -T | grep -v tmpfs | grep -v devtmpfs | grep -v overlay"
	fsTypesOutput, _ := utils.RunCommand("bash", "-c", fsTypesCmd)

	// Get filesystem support in kernel
	supportedFSCmd := "cat /proc/filesystems | grep -v nodev"
	supportedFSOutput, _ := utils.RunCommand("bash", "-c", supportedFSCmd)

	// Check fstab configuration
	fstabCmd := "cat /etc/fstab | grep -v '^#'"
	fstabOutput, _ := utils.RunCommand("bash", "-c", fstabCmd)

	// Process the filesystem types in use
	var fsTypes = make(map[string]int)
	for _, line := range strings.Split(fsTypesOutput, "\n") {
		if line == "" || strings.HasPrefix(line, "Filesystem") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 1 {
			fsType := fields[1]
			fsTypes[fsType]++
		}
	}

	// Check for deprecated or problematic filesystem types
	problematicFS := map[string]string{
		"vfat":     "Limited permissions, not suited for system files",
		"ext2":     "No journaling, consider ext4",
		"ext3":     "Older filesystem, consider ext4",
		"reiserfs": "Deprecated, lack of maintenance",
		"jfs":      "No longer actively maintained",
		"btrfs":    "May have stability issues in older RHEL versions",
	}

	var problemFs []string
	for fs, count := range fsTypes {
		if reason, ok := problematicFS[fs]; ok {
			problemFs = append(problemFs, fmt.Sprintf("%s (%d mounts): %s", fs, count, reason))
		}
	}

	var detail strings.Builder
	detail.WriteString("Filesystems in Use:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fsTypesOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Mounted Filesystems:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(mountedFSOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kernel-Supported Filesystems:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(supportedFSOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Filesystem Configuration in /etc/fstab:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fstabOutput)
	detail.WriteString("\n----\n")

	// Evaluate filesystem types
	if len(problemFs) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d potentially problematic filesystem types", len(problemFs)),
			report.ResultKeyRecommended)

		for _, fs := range problemFs {
			report.AddRecommendation(&check.Result, fs)
		}

		report.AddRecommendation(&check.Result, "Consider migrating to recommended filesystems: ext4, xfs")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-file-systems_managing-storage-devices", rhelVersion))
	} else if len(fsTypes) == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine filesystem types in use",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify filesystem configuration manually")
	} else {
		// Convert fsTypes map to string list for display
		var fsTypesList []string
		for fs, count := range fsTypes {
			fsTypesList = append(fsTypesList, fmt.Sprintf("%s (%d)", fs, count))
		}

		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Using recommended filesystem types: %s", strings.Join(fsTypesList, ", ")),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFilesystemErrors ensures no filesystem errors
func checkFilesystemErrors(r *report.AsciiDocReport) {
	checkID := "storage-filesystem-errors"
	checkName := "Filesystem Errors"
	checkDesc := "Ensures no filesystem errors."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Check dmesg for filesystem errors
	dmesgErrorsCmd := "dmesg | grep -iE '(filesystem|fs error|ext4|xfs|btrfs)' | grep -i error"
	dmesgErrorsOutput, _ := utils.RunCommand("bash", "-c", dmesgErrorsCmd)
	hasDmesgErrors := strings.TrimSpace(dmesgErrorsOutput) != ""

	// Check journalctl for filesystem errors
	journalErrorsCmd := "journalctl -p err..emerg --since '1 week ago' | grep -iE '(filesystem|fs error|ext4|xfs|btrfs)'"
	journalErrorsOutput, _ := utils.RunCommand("bash", "-c", journalErrorsCmd)
	hasJournalErrors := strings.TrimSpace(journalErrorsOutput) != ""

	// Check for automatic filesystem checks (fsck) at boot
	fstabFsckCmd := "grep -v '^#' /etc/fstab | grep -v 'noauto' | awk '{print $4}' | grep -E '(^|,)fsck'"
	fstabFsckOutput, _ := utils.RunCommand("bash", "-c", fstabFsckCmd)
	hasFsckConfig := strings.TrimSpace(fstabFsckOutput) != ""

	// Check for remount-ro option (which would indicate a filesystem error caused a remount)
	// Improved to exclude system filesystems that are intentionally mounted read-only
	remountCmd := "mount | grep -v '/sys/' | grep -v '/proc/' | grep -v 'tmpfs' | grep -v '/dev/' | grep 'ro,'"
	remountOutput, _ := utils.RunCommand("bash", "-c", remountCmd)
	hasRemountRo := strings.TrimSpace(remountOutput) != ""

	// Get space usage for critical mount points
	spaceUsageCmd := "df -h /"
	spaceUsageOutput, _ := utils.RunCommand("bash", "-c", spaceUsageCmd)

	var detail strings.Builder
	if hasDmesgErrors {
		detail.WriteString("Filesystem Errors in Kernel Log:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(dmesgErrorsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No filesystem errors found in kernel log\n\n")
	}

	if hasJournalErrors {
		detail.WriteString("Filesystem Errors in Journal:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(journalErrorsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No filesystem errors found in journal\n\n")
	}

	detail.WriteString("Filesystem Check Configuration in fstab:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasFsckConfig {
		detail.WriteString(fstabFsckOutput)
	} else {
		detail.WriteString("No explicit fsck configuration found\n")
	}
	detail.WriteString("\n----\n\n")

	if hasRemountRo {
		detail.WriteString("Filesystems Mounted Read-Only (possible error state):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(remountOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No regular filesystems remounted read-only\n\n")
	}

	detail.WriteString("Root Filesystem Space Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(spaceUsageOutput)
	detail.WriteString("\n----\n")

	// Evaluate filesystem errors
	if hasDmesgErrors || hasJournalErrors || hasRemountRo {
		check.Result = report.NewResult(report.StatusCritical,
			"Filesystem errors detected",
			report.ResultKeyRequired)

		if hasDmesgErrors {
			report.AddRecommendation(&check.Result, "Review kernel log for filesystem errors")
		}

		if hasJournalErrors {
			report.AddRecommendation(&check.Result, "Review journal for filesystem errors")
		}

		if hasRemountRo {
			report.AddRecommendation(&check.Result, "Filesystem remounted read-only due to errors - recovery needed")
		}

		report.AddRecommendation(&check.Result, "Run filesystem check on affected filesystems")
		report.AddRecommendation(&check.Result, "Check for disk hardware issues with 'smartctl -a /dev/sdX'")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/file-system-checks-managing-storage-devices", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No filesystem errors detected",
			report.ResultKeyNoChange)

		if !hasFsckConfig {
			report.AddRecommendation(&check.Result, "Consider configuring periodic filesystem checks in fstab")
		}
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPartitionAlignment checks partition alignment
func checkPartitionAlignment(r *report.AsciiDocReport) {
	checkID := "storage-partition-alignment"
	checkName := "Partition Alignment"
	checkDesc := "Checks partition alignment for optimal performance."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Get partition information
	partInfoCmd := "parted -l 2>/dev/null || echo 'Could not get partition information'"
	partInfoOutput, _ := utils.RunCommand("bash", "-c", partInfoCmd)

	// Get detailed partition alignment
	partAlignCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -e \"\\nDisk: /dev/$disk\"; fdisk -l /dev/$disk 2>/dev/null | grep -E '^/dev/|start'; done"
	partAlignOutput, _ := utils.RunCommand("bash", "-c", partAlignCmd)

	// Get storage device parameters
	deviceParamsCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -e \"\\nDisk: /dev/$disk\"; cat /sys/block/$disk/queue/optimal_io_size /sys/block/$disk/queue/physical_block_size /sys/block/$disk/alignment_offset 2>/dev/null | tr '\\n' ' '; echo; done"
	deviceParamsOutput, _ := utils.RunCommand("bash", "-c", deviceParamsCmd)

	// Check if we're dealing with SSD or rotational disks
	diskTypeCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -n \"Disk /dev/$disk: \"; cat /sys/block/$disk/queue/rotational 2>/dev/null | grep -q 0 && echo 'SSD' || echo 'HDD'; done"
	diskTypeOutput, _ := utils.RunCommand("bash", "-c", diskTypeCmd)

	// Get mount points information for Red Hat best practices check
	mountPointsCmd := "findmnt -n -l -o TARGET"
	mountPointsOutput, _ := utils.RunCommand("bash", "-c", mountPointsCmd)

	// Check for LUKS encryption
	luksCmd := "lsblk -o NAME,TYPE,MOUNTPOINT,FSTYPE | grep -i 'crypt'"
	luksOutput, _ := utils.RunCommand("bash", "-c", luksCmd)

	// Check if this is a virtual machine
	isVirtualCmd := "systemd-detect-virt || echo 'none'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := isVirtualOutput != "none"

	// Process partition alignment
	var misalignedPartitions []string

	// This is a simplified check - a more accurate check would need to consider
	// the disk's optimal I/O size, physical block size, and partition start sectors
	for _, line := range strings.Split(partAlignOutput, "\n") {
		if strings.HasPrefix(line, "/dev/") && strings.Contains(line, "start") {
			fields := strings.Fields(line)
			if len(fields) > 2 {
				startSector := 0
				fmt.Sscanf(fields[1], "%d", &startSector)

				// For modern disks, partitions should typically start at multiples of 2048 sectors
				// (which is 1MiB with 512-byte sectors)
				if startSector%2048 != 0 && startSector > 2048 {
					misalignedPartitions = append(misalignedPartitions, fields[0])
				}
			}
		}
	}

	// Check for Red Hat best practice partitioning
	requiredMountpoints := []string{"/boot", "/home", "/var", "/tmp", "/var/log", "/var/tmp", "/var/log/audit"}
	baremetalMountpoints := []string{"/boot", "/", "/home", "/tmp", "/var/tmp"}

	// Process mount points
	mountPoints := strings.Split(mountPointsOutput, "\n")
	var missingMountPoints []string

	// Check for required mount points based on environment
	if isVirtual {
		// For virtual environments, separate partitions are optional
		// but we still report for informational purposes
		for _, mp := range requiredMountpoints {
			found := false
			for _, existingMp := range mountPoints {
				if existingMp == mp {
					found = true
					break
				}
			}
			if !found {
				missingMountPoints = append(missingMountPoints, mp)
			}
		}
	} else {
		// For bare-metal, check required mount points
		for _, mp := range baremetalMountpoints {
			found := false
			for _, existingMp := range mountPoints {
				if existingMp == mp {
					found = true
					break
				}
			}
			if !found {
				missingMountPoints = append(missingMountPoints, mp)
			}
		}
	}

	var detail strings.Builder
	detail.WriteString("Partition Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(partInfoOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Partition Alignment Details:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(partAlignOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Parameters (optimal_io_size physical_block_size alignment_offset):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(deviceParamsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Types:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(diskTypeOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Mount Points:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(mountPointsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("LUKS Encryption Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	if luksOutput == "" {
		detail.WriteString("No LUKS encrypted devices detected\n")
	} else {
		detail.WriteString(luksOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("System Type:\n")
	detail.WriteString("[source, bash]\n----\n")
	if isVirtual {
		detail.WriteString("Virtual Machine: " + isVirtualOutput + "\n")
	} else {
		detail.WriteString("Physical Machine (Bare Metal)\n")
	}
	detail.WriteString("\n----\n")

	if len(misalignedPartitions) > 0 {
		detail.WriteString("\nPotentially Misaligned Partitions:\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, part := range misalignedPartitions {
			detail.WriteString(part + "\n")
		}
		detail.WriteString("\n----\n")
	}

	if len(missingMountPoints) > 0 {
		detail.WriteString("\nMissing Recommended Mount Points:\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, mp := range missingMountPoints {
			detail.WriteString(mp + "\n")
		}
		detail.WriteString("\n----\n")
	}

	// Evaluate partition alignment
	if len(misalignedPartitions) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d potentially misaligned partitions", len(misalignedPartitions)),
			report.ResultKeyRecommended)

		for _, part := range misalignedPartitions {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Partition %s may not be optimally aligned", part))
		}

		report.AddRecommendation(&check.Result, "For optimal performance, partitions should be aligned to 1MiB (2048 sectors) boundaries")
		report.AddRecommendation(&check.Result, "Alignment issues may impact performance, especially on SSDs")
		report.AddRecommendation(&check.Result, "Consider backup, repartition, and restore for critical systems")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/assembly_disk-partitions_managing-storage-devices", rhelVersion))
	} else if strings.Contains(partInfoOutput, "Could not get partition information") {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine partition alignment",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Ensure 'parted' is installed to check partition alignment")
		report.AddRecommendation(&check.Result, "Manually verify partition alignment with 'fdisk -l'")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All partitions appear to be properly aligned",
			report.ResultKeyNoChange)
	}

	// Add Red Hat best practices recommendations
	if len(missingMountPoints) > 0 {
		// Keep the existing check.Result if it's already a warning or critical,
		// otherwise create a new advisory if missing recommended mount points
		if check.Result.Status != report.StatusWarning && check.Result.Status != report.StatusCritical {
			check.Result = report.NewResult(report.StatusWarning,
				"Partition layout does not follow Red Hat best practices",
				report.ResultKeyRecommended)
		}

		// Add recommendations based on environment
		if isVirtual {
			report.AddRecommendation(&check.Result, "For virtual environments, separate partitions for /boot, /home, /tmp, and /var/tmp are optional but recommended")
			report.AddRecommendation(&check.Result, "Set up monitoring to check partition usage regularly, and increase virtual disk size if needed")
		} else {
			report.AddRecommendation(&check.Result, "For bare-metal installations, Red Hat recommends separate partitions for /boot, /, /home, /tmp, and /var/tmp")
			report.AddRecommendation(&check.Result, "Separate partitions help ensure system stability and protect data")
			report.AddRecommendation(&check.Result, "Missing recommended partitions: "+strings.Join(missingMountPoints, ", "))
		}

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/installation_guide/performing-a-standard-rhel-installation#recommended-partitioning-scheme_partitioning-guidance", rhelVersion))
	}

	// Add LUKS encryption recommendation if not detected
	if luksOutput == "" {
		report.AddRecommendation(&check.Result, "Consider implementing LUKS encryption for security-sensitive data")
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
