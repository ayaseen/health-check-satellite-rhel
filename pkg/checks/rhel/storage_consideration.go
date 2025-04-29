// pkg/checks/rhel/storage_considerations.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunStorageConsiderationsChecks performs additional storage checks
func RunStorageConsiderationsChecks(r *report.AsciiDocReport) {
	// Check storage performance and tuning
	checkStoragePerformance(r)

	// Check storage redundancy and reliability
	checkStorageReliability(r)

	// Check storage capacity planning
	checkStorageCapacity(r)
}

// checkStoragePerformance checks storage performance and tuning
func checkStoragePerformance(r *report.AsciiDocReport) {
	checkID := "storage-considerations-performance"
	checkName := "Storage Performance"
	checkDesc := "Checks storage performance and tuning."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Check I/O scheduler settings
	schedulerCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -n \"Disk /dev/$disk: \"; cat /sys/block/$disk/queue/scheduler 2>/dev/null; done"
	schedulerOutput, _ := utils.RunCommand("bash", "-c", schedulerCmd)

	// Check readahead settings
	readaheadCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -n \"Disk /dev/$disk readahead: \"; cat /sys/block/$disk/queue/read_ahead_kb 2>/dev/null; done"
	readaheadOutput, _ := utils.RunCommand("bash", "-c", readaheadCmd)

	// Check disk type (SSD vs HDD)
	diskTypeCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -n \"Disk /dev/$disk type: \"; cat /sys/block/$disk/queue/rotational 2>/dev/null | grep -q 0 && echo 'SSD' || echo 'HDD'; done"
	diskTypeOutput, _ := utils.RunCommand("bash", "-c", diskTypeCmd)

	// Check NUMA settings for storage
	numaCmd := "for disk in $(lsblk -d -n -o NAME | grep -vE 'loop|sr'); do echo -n \"Disk /dev/$disk NUMA node: \"; cat /sys/block/$disk/device/numa_node 2>/dev/null || echo 'N/A'; done"
	numaOutput, _ := utils.RunCommand("bash", "-c", numaCmd)

	// Check I/O statistics
	ioStatCmd := "iostat -xd 1 3 | grep -v loop | grep -v sr"
	ioStatOutput, _ := utils.RunCommand("bash", "-c", ioStatCmd)

	// Check RHEL version for appropriate scheduler recommendations
	rhelVersionCmd := "cat /etc/redhat-release | grep -oE '[0-9]+\\.[0-9]+' | cut -d. -f1"
	rhelVersionOutput, _ := utils.RunCommand("bash", "-c", rhelVersionCmd)
	rhelVersion, _ := strconv.Atoi(strings.TrimSpace(rhelVersionOutput))

	// Check if this is a virtual machine
	isVirtualCmd := "systemd-detect-virt 2>/dev/null || echo 'physical'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := strings.TrimSpace(isVirtualOutput) != "physical" && strings.TrimSpace(isVirtualOutput) != "Unknown"

	// Process disk types
	ssdDisks := make(map[string]bool)
	hddDisks := make(map[string]bool)
	nvmeDisks := make(map[string]bool)

	for _, line := range strings.Split(diskTypeOutput, "\n") {
		if !strings.Contains(line, "type:") {
			continue
		}

		parts := strings.Split(line, "type:")
		if len(parts) < 2 {
			continue
		}

		diskName := strings.TrimSpace(strings.Split(parts[0], ":")[0])
		diskName = strings.TrimPrefix(diskName, "Disk ")

		diskType := strings.TrimSpace(parts[1])
		if diskType == "SSD" {
			ssdDisks[diskName] = true
		} else if diskType == "HDD" {
			hddDisks[diskName] = true
		}

		// Check if NVMe device
		if strings.HasPrefix(diskName, "nvme") {
			nvmeDisks[diskName] = true
		}
	}

	var detail strings.Builder
	detail.WriteString("I/O Scheduler Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(schedulerOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Readahead Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(readaheadOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Types:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(diskTypeOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk NUMA Assignments:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(numaOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("I/O Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ioStatOutput)
	detail.WriteString("\n----\n")

	// Check scheduler settings against disk types
	var schedulerIssues []string
	for _, line := range strings.Split(schedulerOutput, "\n") {
		if !strings.Contains(line, "Disk /dev/") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		diskName := strings.TrimSpace(parts[0])
		diskName = strings.TrimPrefix(diskName, "Disk ")

		scheduler := strings.TrimSpace(parts[1])
		activeScheduler := ""

		// Extract the active scheduler (the one in [brackets])
		if strings.Contains(scheduler, "[") && strings.Contains(scheduler, "]") {
			start := strings.Index(scheduler, "[") + 1
			end := strings.Index(scheduler, "]")
			if start < end {
				activeScheduler = scheduler[start:end]
			}
		}

		// Apply recommendations based on RHEL version
		if rhelVersion >= 8 {
			// RHEL 8+ recommendations based on official documentation
			if isVirtual {
				// For virtual guests, mq-deadline is the primary recommendation
				// With multi-queue capable HBA drivers, none is also acceptable
				if activeScheduler != "mq-deadline" && activeScheduler != "none" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (virtual disk using %s scheduler instead of 'mq-deadline' or 'none')", diskName, activeScheduler))
				}
			} else if nvmeDisks[diskName] {
				// For NVMe devices, none is specifically recommended
				if activeScheduler != "none" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (NVMe disk using %s scheduler instead of 'none')", diskName, activeScheduler))
				}
			} else if ssdDisks[diskName] {
				// For high-performance SSDs, none is recommended, with kyber as alternative
				if activeScheduler != "none" && activeScheduler != "kyber" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (SSD using %s scheduler instead of 'none' or 'kyber')", diskName, activeScheduler))
				}
			} else if hddDisks[diskName] {
				// For traditional HDDs, mq-deadline or bfq are recommended
				if activeScheduler != "mq-deadline" && activeScheduler != "bfq" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (HDD using %s scheduler instead of 'mq-deadline' or 'bfq')", diskName, activeScheduler))
				}
			}
		} else {
			// Pre-RHEL 8 recommendations
			if ssdDisks[diskName] {
				// For SSDs, 'none' or 'noop' are typically best
				if activeScheduler != "none" && activeScheduler != "noop" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (SSD using %s scheduler instead of 'none' or 'noop')", diskName, activeScheduler))
				}
			} else if hddDisks[diskName] {
				// For HDDs, 'deadline' or 'cfq' are typically better
				if activeScheduler != "deadline" && activeScheduler != "cfq" {
					schedulerIssues = append(schedulerIssues,
						fmt.Sprintf("%s (HDD using %s scheduler instead of 'deadline' or 'cfq')", diskName, activeScheduler))
				}
			}
		}
	}

	// Check for high I/O wait times in iostat output
	highIoWait := false
	highAvgQuSize := false

	for _, line := range strings.Split(ioStatOutput, "\n") {
		if !strings.HasPrefix(line, "sd") && !strings.HasPrefix(line, "nvme") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		// Check avgqu-sz (average queue size)
		avgQuSize := 0.0
		fmt.Sscanf(fields[8], "%f", &avgQuSize)
		if avgQuSize > 4.0 {
			highAvgQuSize = true
		}

		// Check await (average wait time)
		await := 0.0
		fmt.Sscanf(fields[9], "%f", &await)
		if await > 20.0 {
			highIoWait = true
		}
	}

	// Evaluate storage performance
	if len(schedulerIssues) > 0 || highIoWait || highAvgQuSize {
		check.Result = report.NewResult(report.StatusWarning,
			"Storage performance could be improved",
			report.ResultKeyRecommended)

		if len(schedulerIssues) > 0 {
			report.AddRecommendation(&check.Result, "Suboptimal I/O scheduler settings detected for:")
			for _, disk := range schedulerIssues {
				report.AddRecommendation(&check.Result, "- "+disk)
			}

			if rhelVersion >= 8 {
				report.AddRecommendation(&check.Result, "For RHEL 8+:")
				report.AddRecommendation(&check.Result, "  - For virtual guests: use 'mq-deadline' scheduler (primary recommendation)")
				report.AddRecommendation(&check.Result, "    With a multi-queue capable HBA driver, 'none' is also suitable")
				report.AddRecommendation(&check.Result, "  - For NVMe devices: use 'none' scheduler (Red Hat specifically recommends not changing this)")
				report.AddRecommendation(&check.Result, "  - For high-performance SSDs: use 'none' or alternatively 'kyber'")
				report.AddRecommendation(&check.Result, "  - For traditional HDDs: use 'mq-deadline' or 'bfq'")
			} else {
				report.AddRecommendation(&check.Result, "For SSDs, use 'none' or 'noop' scheduler")
				report.AddRecommendation(&check.Result, "For HDDs, use 'deadline' or 'cfq' scheduler")
			}

			report.AddRecommendation(&check.Result, "Example: echo scheduler_name > /sys/block/device_name/queue/scheduler")
		}

		if highIoWait {
			report.AddRecommendation(&check.Result, "High I/O wait times detected, indicating storage bottlenecks")
			report.AddRecommendation(&check.Result, "Consider monitoring I/O performance with iostat or iotop")
		}

		if highAvgQuSize {
			report.AddRecommendation(&check.Result, "High I/O queue sizes detected, indicating storage saturation")
			report.AddRecommendation(&check.Result, "Consider upgrading storage or optimizing workloads")
		}

		// Add RHEL documentation reference directly
		rhelVersionStr := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/setting-the-disk-scheduler_monitoring-and-managing-system-status-and-performance", rhelVersionStr, rhelVersionStr))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Storage performance settings appear to be appropriate",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkStorageReliability checks storage redundancy and reliability
func checkStorageReliability(r *report.AsciiDocReport) {
	checkID := "storage-considerations-reliability"
	checkName := "Storage Reliability"
	checkDesc := "Checks storage redundancy and reliability."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Check for RAID configuration
	raidCmd := "cat /proc/mdstat 2>/dev/null || echo 'No software RAID detected'"
	raidOutput, _ := utils.RunCommand("bash", "-c", raidCmd)
	hasSoftwareRaid := !strings.Contains(raidOutput, "No software RAID detected") &&
		!strings.Contains(raidOutput, "Personalities : ")

	// Check for hardware RAID
	hwRaidCmd := "lspci | grep -i raid || echo 'No hardware RAID controller detected'"
	hwRaidOutput, _ := utils.RunCommand("bash", "-c", hwRaidCmd)
	hasHardwareRaid := !strings.Contains(hwRaidOutput, "No hardware RAID controller detected")

	// Check for LVM configuration
	lvmCmd := "lvs 2>/dev/null || echo 'No LVM volumes detected'"
	lvmOutput, _ := utils.RunCommand("bash", "-c", lvmCmd)
	hasLVM := !strings.Contains(lvmOutput, "No LVM volumes detected")

	// Check for multipath configuration
	multipathCmd := "multipath -ll 2>/dev/null || echo 'No multipath devices detected'"
	multipathOutput, _ := utils.RunCommand("bash", "-c", multipathCmd)
	hasMultipath := !strings.Contains(multipathOutput, "No multipath devices detected")

	// Check disk health (only for physical systems)
	isVirtualCmd := "systemd-detect-virt 2>/dev/null || echo 'physical'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)
	isVirtual := strings.TrimSpace(isVirtualOutput) != "physical" && strings.TrimSpace(isVirtualOutput) != "Unknown"

	var smartDataOutput string
	if !isVirtual {
		smartDataCmd := "for disk in $(lsblk -d -n -o NAME | grep -v loop | grep -v sr | grep -v dm); do echo \"SMART data for /dev/$disk:\"; smartctl -H /dev/$disk 2>/dev/null || echo 'smartctl not available'; echo; done"
		smartDataOutput, _ = utils.RunCommand("bash", "-c", smartDataCmd)
	} else {
		smartDataOutput = "Virtual machine - SMART data not applicable"
	}

	// Check if any RAIDs are degraded
	raidDegraded := false
	if hasSoftwareRaid {
		for _, line := range strings.Split(raidOutput, "\n") {
			if strings.Contains(line, "degraded") || strings.Contains(line, "_") {
				raidDegraded = true
				break
			}
		}
	}

	// Check if any disks are failing (if we have SMART data)
	disksFailingPredictive := false
	if !isVirtual && !strings.Contains(smartDataOutput, "smartctl not available") {
		for _, line := range strings.Split(smartDataOutput, "\n") {
			if strings.Contains(line, "FAILED") || strings.Contains(line, "failed") {
				disksFailingPredictive = true
				break
			}
		}
	}

	var detail strings.Builder
	detail.WriteString("Software RAID Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(raidOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Hardware RAID Controller:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hwRaidOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("LVM Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(lvmOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multipath Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(multipathOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Health Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(smartDataOutput)
	detail.WriteString("\n----\n")

	// Determine if we have any redundancy
	hasAnyRedundancy := hasSoftwareRaid || hasHardwareRaid || (hasLVM && hasMultipath)

	// Evaluate storage reliability
	if disksFailingPredictive {
		check.Result = report.NewResult(report.StatusCritical,
			"Storage drives failing predictive health checks",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Replace failing drives immediately")
		report.AddRecommendation(&check.Result, "Check system logs for I/O errors")
		report.AddRecommendation(&check.Result, "Verify backups are current before taking any action")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-software-raid_managing-storage-devices", rhelVersion, rhelVersion))
	} else if raidDegraded {
		check.Result = report.NewResult(report.StatusCritical,
			"RAID array(s) in degraded state",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Replace failed disks and rebuild RAID array")
		report.AddRecommendation(&check.Result, "Monitor rebuild progress with 'cat /proc/mdstat'")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-software-raid_managing-storage-devices#recovering-a-degraded-raid-array_managing-software-raid", rhelVersion, rhelVersion))
	} else if !hasAnyRedundancy && !isVirtual {
		check.Result = report.NewResult(report.StatusWarning,
			"No storage redundancy detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider implementing RAID for critical systems")
		report.AddRecommendation(&check.Result, "Ensure regular backups are in place")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-software-raid_managing-storage-devices", rhelVersion, rhelVersion))
	} else {
		if isVirtual {
			check.Result = report.NewResult(report.StatusInfo,
				"Virtual machine - storage redundancy managed by hypervisor",
				report.ResultKeyNoChange)
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"Storage appears to have redundancy configured",
				report.ResultKeyNoChange)
		}
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkStorageCapacity checks storage capacity planning
func checkStorageCapacity(r *report.AsciiDocReport) {
	checkID := "storage-considerations-capacity"
	checkName := "Storage Capacity"
	checkDesc := "Checks storage capacity planning."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryStorage)

	// Get disk usage
	diskUsageCmd := "df -h -T"
	diskUsageOutput, _ := utils.RunCommand("bash", "-c", diskUsageCmd)

	// Get inode usage
	inodeUsageCmd := "df -i -T | grep -v tmpfs"
	inodeUsageOutput, _ := utils.RunCommand("bash", "-c", inodeUsageCmd)

	// Get disk usage trend
	diskTrendCmd := "for i in $(seq 1 3); do date; df -h | grep -vE 'tmpfs|devtmpfs'; sleep 1; done"
	diskTrendOutput, _ := utils.RunCommand("bash", "-c", diskTrendCmd)

	// Get historical growth from system logs if available
	diskHistoryCmd := "grep -a 'filesystem' /var/log/messages 2>/dev/null | grep 'running out' || echo 'No historical capacity alerts found'"
	diskHistoryOutput, _ := utils.RunCommand("bash", "-c", diskHistoryCmd)

	// Parse current disk usage and identify high usage filesystems
	highUsageFilesystems := []string{}
	criticalFilesystems := []string{}

	for _, line := range strings.Split(diskUsageOutput, "\n") {
		if !strings.HasPrefix(line, "/") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		usageStr := fields[5]
		if !strings.HasSuffix(usageStr, "%") {
			continue
		}

		usage, err := strconv.Atoi(usageStr[:len(usageStr)-1])
		if err != nil {
			continue
		}

		mountpoint := fields[6]

		if usage >= 90 {
			criticalFilesystems = append(criticalFilesystems, fmt.Sprintf("%s (%d%%)", mountpoint, usage))
		} else if usage >= 80 {
			highUsageFilesystems = append(highUsageFilesystems, fmt.Sprintf("%s (%d%%)", mountpoint, usage))
		}
	}

	// Parse inode usage and identify high usage filesystems
	highInodeFilesystems := []string{}
	criticalInodeFilesystems := []string{}

	for _, line := range strings.Split(inodeUsageOutput, "\n") {
		if !strings.HasPrefix(line, "/") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		usageStr := fields[5]
		if !strings.HasSuffix(usageStr, "%") {
			continue
		}

		usage, err := strconv.Atoi(usageStr[:len(usageStr)-1])
		if err != nil {
			continue
		}

		mountpoint := fields[6]

		if usage >= 90 {
			criticalInodeFilesystems = append(criticalInodeFilesystems, fmt.Sprintf("%s (%d%%)", mountpoint, usage))
		} else if usage >= 80 {
			highInodeFilesystems = append(highInodeFilesystems, fmt.Sprintf("%s (%d%%)", mountpoint, usage))
		}
	}

	var detail strings.Builder
	detail.WriteString("Filesystem Disk Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(diskUsageOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Filesystem Inode Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(inodeUsageOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Disk Usage Trend:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(diskTrendOutput)
	detail.WriteString("\n----\n\n")

	if !strings.Contains(diskHistoryOutput, "No historical capacity alerts found") {
		detail.WriteString("Historical Capacity Alerts:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(diskHistoryOutput)
		detail.WriteString("\n----\n\n")
	}

	if len(criticalFilesystems) > 0 {
		detail.WriteString("Critical Usage Filesystems (>90%):\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, fs := range criticalFilesystems {
			detail.WriteString("- " + fs + "\n")
		}
		detail.WriteString("\n----\n\n")
	}

	if len(highUsageFilesystems) > 0 {
		detail.WriteString("High Usage Filesystems (>80%):\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, fs := range highUsageFilesystems {
			detail.WriteString("- " + fs + "\n")
		}
		detail.WriteString("\n----\n\n")
	}

	if len(criticalInodeFilesystems) > 0 {
		detail.WriteString("Critical Inode Usage Filesystems (>90%):\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, fs := range criticalInodeFilesystems {
			detail.WriteString("- " + fs + "\n")
		}
		detail.WriteString("\n----\n\n")
	}

	if len(highInodeFilesystems) > 0 {
		detail.WriteString("High Inode Usage Filesystems (>80%):\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, fs := range highInodeFilesystems {
			detail.WriteString("- " + fs + "\n")
		}
		detail.WriteString("\n----\n")
	}

	// Evaluate storage capacity
	if len(criticalFilesystems) > 0 || len(criticalInodeFilesystems) > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("Critical storage capacity issues detected on %d filesystem(s)",
				len(criticalFilesystems)+len(criticalInodeFilesystems)),
			report.ResultKeyRequired)

		for _, fs := range criticalFilesystems {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Urgently address space usage on %s", fs))
		}

		for _, fs := range criticalInodeFilesystems {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Urgently address inode usage on %s", fs))
		}

		report.AddRecommendation(&check.Result, "Use 'du -sh /*' to identify large directories")
		report.AddRecommendation(&check.Result, "For inode usage, look for directories with many small files")
		report.AddRecommendation(&check.Result, "Consider expanding filesystem capacity or cleaning up unnecessary files")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-file-systems_managing-storage-devices", rhelVersion, rhelVersion))
	} else if len(highUsageFilesystems) > 0 || len(highInodeFilesystems) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High storage usage detected on %d filesystem(s)",
				len(highUsageFilesystems)+len(highInodeFilesystems)),
			report.ResultKeyRecommended)

		for _, fs := range highUsageFilesystems {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Monitor space usage on %s", fs))
		}

		for _, fs := range highInodeFilesystems {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Monitor inode usage on %s", fs))
		}

		report.AddRecommendation(&check.Result, "Plan for capacity expansion before filesystems reach 90% usage")
		report.AddRecommendation(&check.Result, "Implement storage monitoring to track growth trends")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_storage_devices/managing-file-systems_managing-storage-devices", rhelVersion, rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Storage capacity appears to be adequate",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
