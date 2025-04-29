// pkg/checks/rhel/performance.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunPerformanceChecks performs additional system performance related checks
func RunPerformanceChecks(r *report.AsciiDocReport) {
	// Check system performance metrics
	checkSystemPerformance(r)

	// Check for performance bottlenecks
	checkPerformanceBottlenecks(r)

	// Check system caches
	checkSystemCaches(r)
}

// checkSystemPerformance evaluates overall system performance
func checkSystemPerformance(r *report.AsciiDocReport) {
	checkID := "system-performance"
	checkName := "System Performance"
	checkDesc := "Evaluates overall system performance metrics."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get system uptime and load averages
	uptimeCmd := "uptime"
	uptimeOutput, err := utils.RunCommand("bash", "-c", uptimeCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine system uptime and load", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'uptime' command is available.")
		r.AddCheck(check)
		return
	}

	// Get vmstat output
	vmstatCmd := "vmstat 1 3"
	vmstatOutput, _ := utils.RunCommand("bash", "-c", vmstatCmd)

	// Get memory usage
	freeCmd := "free -h"
	freeOutput, _ := utils.RunCommand("bash", "-c", freeCmd)

	// Get disk IO statistics
	iostatCmd := "iostat -xz 1 3"
	iostatOutput, _ := utils.RunCommand("bash", "-c", iostatCmd)

	// Get network statistics
	netstatCmd := "netstat -s | grep -E 'segments retransmited|bad segments received|resets received'"
	netstatOutput, _ := utils.RunCommand("bash", "-c", netstatCmd)

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	perfDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/", rhelVersion)

	var detail strings.Builder
	detail.WriteString("System Uptime and Load:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(uptimeOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nVMStat Output:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(vmstatOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nMemory Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(freeOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nDisk I/O Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(iostatOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nNetwork Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(netstatOutput)
	detail.WriteString("\n----\n")

	// Parse load averages from uptime
	loadAvgs := []float64{0.0, 0.0, 0.0}
	uptimeParts := strings.Split(uptimeOutput, "load average:")
	if len(uptimeParts) > 1 {
		loads := strings.Split(strings.TrimSpace(uptimeParts[1]), ",")
		if len(loads) >= 3 {
			loadAvgs[0], _ = strconv.ParseFloat(strings.TrimSpace(loads[0]), 64)
			loadAvgs[1], _ = strconv.ParseFloat(strings.TrimSpace(loads[1]), 64)
			loadAvgs[2], _ = strconv.ParseFloat(strings.TrimSpace(loads[2]), 64)
		}
	}

	// Get CPU count to evaluate load average
	cpuCountCmd := "nproc"
	cpuCountOutput, _ := utils.RunCommand("bash", "-c", cpuCountCmd)
	cpuCount, _ := strconv.Atoi(strings.TrimSpace(cpuCountOutput))
	if cpuCount == 0 {
		cpuCount = 1 // Prevent division by zero
	}

	// Parse vmstat for IO wait and system time
	ioWait := 0.0
	sysTime := 0.0
	vmstatLines := strings.Split(vmstatOutput, "\n")
	if len(vmstatLines) > 2 {
		// Average the values from the samples (skip first line)
		for i := 2; i < len(vmstatLines); i++ {
			fields := strings.Fields(vmstatLines[i])
			if len(fields) >= 16 {
				// IO wait is usually column 16
				wait, _ := strconv.ParseFloat(fields[15], 64)
				ioWait += wait

				// System time is usually column 14
				sys, _ := strconv.ParseFloat(fields[13], 64)
				sysTime += sys
			}
		}

		// Calculate averages
		if len(vmstatLines) > 2 {
			ioWait /= float64(len(vmstatLines) - 2)
			sysTime /= float64(len(vmstatLines) - 2)
		}
	}

	// Check for performance issues
	performanceIssues := []string{}

	// Check load average
	if loadAvgs[0] > float64(cpuCount)*1.5 {
		performanceIssues = append(performanceIssues,
			fmt.Sprintf("High load average (%.2f) exceeds 1.5x CPU count (%d)", loadAvgs[0], cpuCount))
	}

	// Check IO wait
	if ioWait > 10.0 {
		performanceIssues = append(performanceIssues,
			fmt.Sprintf("High IO wait percentage: %.1f%%", ioWait))
	}

	// Check system time
	if sysTime > 20.0 {
		performanceIssues = append(performanceIssues,
			fmt.Sprintf("High system CPU time: %.1f%%", sysTime))
	}

	// Check for network retransmissions
	if strings.Contains(netstatOutput, "segments retransmited") {
		for _, line := range strings.Split(netstatOutput, "\n") {
			if strings.Contains(line, "segments retransmited") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					retrans, err := strconv.Atoi(fields[0])
					if err == nil && retrans > 1000 {
						performanceIssues = append(performanceIssues,
							fmt.Sprintf("High TCP retransmissions: %d", retrans))
					}
				}
			}
		}
	}

	// Evaluate system performance
	if len(performanceIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d performance issues", len(performanceIssues)),
			report.ResultKeyRecommended)

		for _, issue := range performanceIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if loadAvgs[0] > float64(cpuCount)*1.5 {
			report.AddRecommendation(&check.Result, "Investigate high system load with 'top' and 'ps'")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smanaging-cpu-resources", perfDocURL))
		}

		if ioWait > 10.0 {
			report.AddRecommendation(&check.Result, "Investigate IO bottlenecks with 'iostat' and 'iotop'")
			report.AddRecommendation(&check.Result, "Consider optimizing disk subsystem or adding SSDs")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smonitoring-and-managing-storage-performance", perfDocURL))
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System performance metrics are within acceptable ranges",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPerformanceBottlenecks checks for specific performance bottlenecks
func checkPerformanceBottlenecks(r *report.AsciiDocReport) {
	checkID := "performance-bottlenecks"
	checkName := "Performance Bottlenecks"
	checkDesc := "Checks for specific performance bottlenecks in the system."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get process list sorted by memory usage
	topMemoryCmd := "ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -11"
	topMemoryOutput, err := utils.RunCommand("bash", "-c", topMemoryCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine memory usage by process", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'ps' command is available.")
		r.AddCheck(check)
		return
	}

	// Get top CPU consuming processes
	topCPUCmd := "ps -eo pid,cmd,%cpu --sort=-%cpu | head -11"
	topCPUOutput, _ := utils.RunCommand("bash", "-c", topCPUCmd)

	// Get disk usage sorted by size
	duCmd := "du -h /var /opt /usr --max-depth=2 2>/dev/null | sort -hr | head -20"
	duOutput, _ := utils.RunCommand("bash", "-c", duCmd)

	// Check for OOM killer events
	oomCmd := "grep -i 'Out of memory' /var/log/messages /var/log/syslog 2>/dev/null | tail -5"
	oomOutput, _ := utils.RunCommand("bash", "-c", oomCmd)

	// Check for slow disk IO
	slowDiskCmd := "grep -i 'blocked for more than' /var/log/messages /var/log/syslog /var/log/kern.log 2>/dev/null | tail -5"
	slowDiskOutput, _ := utils.RunCommand("bash", "-c", slowDiskCmd)

	// Check swap usage
	swapCmd := "free -m | awk '/^Swap:/ {print $3}'"
	swapOutput, _ := utils.RunCommand("bash", "-c", swapCmd)

	// Check for zombie processes
	zombieCmd := "ps -eo stat | grep -c '^Z'"
	zombieOutput, _ := utils.RunCommand("bash", "-c", zombieCmd)

	// Check for failed systemd services
	failedServicesCmd := "systemctl list-units --state=failed --no-legend"
	failedServicesOutput, _ := utils.RunCommand("bash", "-c", failedServicesCmd)

	// Check for process count vs ulimit
	processCountCmd := "echo \"$(ps -e | wc -l) $(ulimit -u)\""
	processCountOutput, _ := utils.RunCommand("bash", "-c", processCountCmd)

	// Check for open file descriptors count
	fdCountCmd := "echo \"$(lsof 2>/dev/null | wc -l) $(ulimit -n)\""
	fdCountOutput, _ := utils.RunCommand("bash", "-c", fdCountCmd)

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	perfDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Top Memory Consuming Processes:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(topMemoryOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Top CPU Consuming Processes:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(topCPUOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Largest Directories:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(duOutput)
	detail.WriteString("\n----\n\n")

	if strings.TrimSpace(oomOutput) != "" {
		detail.WriteString("OOM Killer Events:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(oomOutput)
		detail.WriteString("\n----\n\n")
	}

	if strings.TrimSpace(slowDiskOutput) != "" {
		detail.WriteString("Slow Disk I/O Events:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(slowDiskOutput)
		detail.WriteString("\n----\n\n")
	}

	detail.WriteString("Swap Usage (MB):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(swapOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Zombie Processes Count:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(zombieOutput)
	detail.WriteString("\n----\n\n")

	if strings.TrimSpace(failedServicesOutput) != "" {
		detail.WriteString("Failed Systemd Services:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(failedServicesOutput)
		detail.WriteString("\n----\n\n")
	}

	detail.WriteString("Process Count vs Ulimit:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(processCountOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Open File Descriptors Count vs Limit:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fdCountOutput)
	detail.WriteString("\n----\n\n")

	// Parse process memory usage
	highMemoryProcesses := []string{}
	processList := strings.Split(topMemoryOutput, "\n")

	// Skip header
	if len(processList) > 1 {
		processList = processList[1:]
	}

	for _, line := range processList {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			memUsageStr := fields[len(fields)-1]
			memUsage, err := strconv.ParseFloat(memUsageStr, 64)
			if err == nil && memUsage > 30.0 {
				// Get the command name
				cmd := "Unknown"
				if len(fields) > 3 {
					cmdFields := fields[:len(fields)-1]
					if len(cmdFields) > 2 {
						cmd = strings.Join(cmdFields[2:], " ")
					}
				}
				highMemoryProcesses = append(highMemoryProcesses,
					fmt.Sprintf("Process using %.1f%% of memory: %s", memUsage, cmd))
			}
		}
	}

	// Parse CPU usage for high CPU processes
	highCPUProcesses := []string{}
	cpuProcessList := strings.Split(topCPUOutput, "\n")

	// Skip header
	if len(cpuProcessList) > 1 {
		cpuProcessList = cpuProcessList[1:]
	}

	for _, line := range cpuProcessList {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			cpuUsageStr := fields[len(fields)-1]
			cpuUsage, err := strconv.ParseFloat(cpuUsageStr, 64)
			if err == nil && cpuUsage > 80.0 {
				// Get the command name
				cmd := "Unknown"
				if len(fields) > 2 {
					cmdFields := fields[:len(fields)-1]
					if len(cmdFields) > 1 {
						cmd = strings.Join(cmdFields[1:], " ")
					}
				}
				highCPUProcesses = append(highCPUProcesses,
					fmt.Sprintf("Process using %.1f%% of CPU: %s", cpuUsage, cmd))
			}
		}
	}

	// Parse swap usage
	swapUsage := 0
	swapUsageStr := strings.TrimSpace(swapOutput)
	swapUsageVal, err := strconv.Atoi(swapUsageStr)
	if err == nil {
		swapUsage = swapUsageVal
	}

	// Parse zombie process count
	zombieCount := 0
	zombieCountStr := strings.TrimSpace(zombieOutput)
	zombieCountVal, err := strconv.Atoi(zombieCountStr)
	if err == nil {
		zombieCount = zombieCountVal
	}

	// Parse process count vs ulimit
	processCount := 0
	processLimit := 1 // Default to 1 to avoid division by zero
	processFields := strings.Fields(processCountOutput)
	if len(processFields) >= 2 {
		processCount, _ = strconv.Atoi(processFields[0])
		processLimit, _ = strconv.Atoi(processFields[1])
		if processLimit == 0 {
			processLimit = 1 // Avoid division by zero
		}
	}

	// Parse file descriptors count vs limit
	fdCount := 0
	fdLimit := 1 // Default to 1 to avoid division by zero
	fdFields := strings.Fields(fdCountOutput)
	if len(fdFields) >= 2 {
		fdCount, _ = strconv.Atoi(fdFields[0])
		fdLimit, _ = strconv.Atoi(fdFields[1])
		if fdLimit == 0 {
			fdLimit = 1 // Avoid division by zero
		}
	}

	// Define issues list
	bottleneckIssues := []string{}

	// Add high memory processes to issues
	bottleneckIssues = append(bottleneckIssues, highMemoryProcesses...)

	// Add high CPU processes to issues
	bottleneckIssues = append(bottleneckIssues, highCPUProcesses...)

	// Check for OOM events
	if strings.TrimSpace(oomOutput) != "" {
		bottleneckIssues = append(bottleneckIssues, "Out of Memory killer events detected")
	}

	// Check for slow disk events
	if strings.TrimSpace(slowDiskOutput) != "" {
		bottleneckIssues = append(bottleneckIssues, "Slow disk I/O events detected")
	}

	// Check for swap usage
	if swapUsage > 0 {
		bottleneckIssues = append(bottleneckIssues, fmt.Sprintf("Swap usage detected: %d MB", swapUsage))
	}

	// Check for zombie processes
	if zombieCount > 0 {
		bottleneckIssues = append(bottleneckIssues, fmt.Sprintf("Zombie processes detected: %d", zombieCount))
	}

	// Check for failed services
	if strings.TrimSpace(failedServicesOutput) != "" {
		bottleneckIssues = append(bottleneckIssues, "Failed systemd services detected")
	}

	// Check for high process count
	if processCount > (processLimit * 75 / 100) {
		bottleneckIssues = append(bottleneckIssues,
			fmt.Sprintf("High process count: %d (%.1f%% of limit %d)",
				processCount, float64(processCount)/float64(processLimit)*100, processLimit))
	}

	// Check for high file descriptor usage
	if fdCount > (fdLimit * 75 / 100) {
		bottleneckIssues = append(bottleneckIssues,
			fmt.Sprintf("High file descriptor usage: %d (%.1f%% of limit %d)",
				fdCount, float64(fdCount)/float64(fdLimit)*100, fdLimit))
	}

	// Create performance summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Performance Metrics Summary:\n\n")
	detail.WriteString("|===\n")
	detail.WriteString("|Metric|Value|Status\n\n")

	// Memory processes
	if len(highMemoryProcesses) > 0 {
		detail.WriteString(fmt.Sprintf("|High Memory Processes|%d|Warning\n", len(highMemoryProcesses)))
	} else {
		detail.WriteString("|Memory Process Usage|Normal|OK\n")
	}

	// CPU processes
	if len(highCPUProcesses) > 0 {
		detail.WriteString(fmt.Sprintf("|High CPU Processes|%d|Warning\n", len(highCPUProcesses)))
	} else {
		detail.WriteString("|CPU Process Usage|Normal|OK\n")
	}

	// Swap usage
	swapStatus := "OK"
	if swapUsage > 0 {
		swapStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("|Swap Usage|%d MB|%s\n", swapUsage, swapStatus))

	// Zombie processes
	zombieStatus := "OK"
	if zombieCount > 0 {
		zombieStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("|Zombie Processes|%d|%s\n", zombieCount, zombieStatus))

	// Failed services
	if strings.TrimSpace(failedServicesOutput) != "" {
		detail.WriteString("|Systemd Services|Failed services present|Warning\n")
	} else {
		detail.WriteString("|Systemd Services|All operational|OK\n")
	}

	// Process count
	processStatus := "OK"
	processPercentage := float64(processCount) / float64(processLimit) * 100
	if processPercentage > 75 {
		processStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("|Process Count|%d / %d (%.1f%%)|%s\n",
		processCount, processLimit, processPercentage, processStatus))

	// File descriptors
	fdStatus := "OK"
	fdPercentage := float64(fdCount) / float64(fdLimit) * 100
	if fdPercentage > 75 {
		fdStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("|File Descriptors|%d / %d (%.1f%%)|%s\n",
		fdCount, fdLimit, fdPercentage, fdStatus))

	detail.WriteString("|===\n\n")

	// Evaluate performance bottlenecks
	if len(bottleneckIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d performance bottlenecks", len(bottleneckIssues)),
			report.ResultKeyRecommended)

		for _, issue := range bottleneckIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if len(highMemoryProcesses) > 0 {
			report.AddRecommendation(&check.Result, "Review memory usage of high-consumption processes")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smanaging-memory", perfDocURL))
		}

		if len(highCPUProcesses) > 0 {
			report.AddRecommendation(&check.Result, "Investigate high CPU usage processes")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smanaging-cpu-resources", perfDocURL))
		}

		if strings.TrimSpace(oomOutput) != "" {
			report.AddRecommendation(&check.Result, "Consider increasing system memory or tuning application memory usage")
			report.AddRecommendation(&check.Result, "Check for memory leaks in applications")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smonitoring-memory-usage", perfDocURL))
		}

		if strings.TrimSpace(slowDiskOutput) != "" {
			report.AddRecommendation(&check.Result, "Investigate disk subsystem for bottlenecks")
			report.AddRecommendation(&check.Result, "Consider upgrading to SSDs or optimizing storage configuration")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%smonitoring-and-managing-storage-performance", perfDocURL))
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant performance bottlenecks detected",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSystemCaches checks file system and other caches configurations
func checkSystemCaches(r *report.AsciiDocReport) {
	checkID := "system-caches"
	checkName := "System Caches"
	checkDesc := "Checks file system and other caches configurations."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get information about memory caches
	cacheInfoCmd := "cat /proc/meminfo | grep -i cache"
	cacheInfoOutput, err := utils.RunCommand("bash", "-c", cacheInfoCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine cache information", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure /proc/meminfo is readable.")
		r.AddCheck(check)
		return
	}

	// Get sysctl cache parameters
	sysctlCacheCmd := "sysctl -a 2>/dev/null | grep -E 'vm.dirty|vm.vfs_cache|vm.swappiness'"
	sysctlCacheOutput, _ := utils.RunCommand("bash", "-c", sysctlCacheCmd)

	// Get current dirty page status
	dirtyPagesCmd := "cat /proc/vmstat | grep -E 'nr_dirty|nr_writeback'"
	dirtyPagesOutput, _ := utils.RunCommand("bash", "-c", dirtyPagesCmd)

	// Get details on file system caches
	slabtopCmd := "slabtop -o -s c 2>/dev/null | head -20"
	slabtopOutput, _ := utils.RunCommand("bash", "-c", slabtopCmd)

	if strings.Contains(slabtopOutput, "command not found") {
		slabtopOutput = "slabtop command not available"
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	sysctlDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/setting-limits-for-systems-resources-for-application-performance", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Memory Cache Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cacheInfoOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nCache-related Kernel Parameters:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sysctlCacheOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nDirty Pages Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dirtyPagesOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nKernel Slab Cache Details:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(slabtopOutput)
	detail.WriteString("\n----\n")

	// Extract values of interest
	dirtyRatio := 0
	dirtyBgRatio := 0
	vfsCachePressure := 0

	for _, line := range strings.Split(sysctlCacheOutput, "\n") {
		if strings.Contains(line, "vm.dirty_ratio") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				dirtyRatio, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.Contains(line, "vm.dirty_background_ratio") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				dirtyBgRatio, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.Contains(line, "vm.vfs_cache_pressure") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				vfsCachePressure, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
	}

	// Parse dirty pages information for reporting
	detail.WriteString("\nDirty Pages Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	for _, line := range strings.Split(dirtyPagesOutput, "\n") {
		if strings.HasPrefix(line, "nr_dirty") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				dirtyPagesValue, _ := strconv.Atoi(parts[1])
				detail.WriteString(fmt.Sprintf("Current dirty pages: %d\n", dirtyPagesValue))
			}
		}
	}
	detail.WriteString("\n----\n")

	// Check for issues
	cacheIssues := []string{}

	// Check dirty ratio configuration
	if dirtyRatio > 40 {
		cacheIssues = append(cacheIssues, fmt.Sprintf("vm.dirty_ratio is set too high: %d%%", dirtyRatio))
	} else if dirtyRatio < 5 {
		cacheIssues = append(cacheIssues, fmt.Sprintf("vm.dirty_ratio is set too low: %d%%", dirtyRatio))
	}

	// Check background dirty ratio
	if dirtyBgRatio > 30 {
		cacheIssues = append(cacheIssues, fmt.Sprintf("vm.dirty_background_ratio is set too high: %d%%", dirtyBgRatio))
	}

	// Check VFS cache pressure
	if vfsCachePressure > 200 {
		cacheIssues = append(cacheIssues, fmt.Sprintf("vm.vfs_cache_pressure is set very high: %d", vfsCachePressure))
	} else if vfsCachePressure < 50 {
		cacheIssues = append(cacheIssues, fmt.Sprintf("vm.vfs_cache_pressure is set low: %d", vfsCachePressure))
	}

	// Evaluate cache settings
	if len(cacheIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d cache configuration issues", len(cacheIssues)),
			report.ResultKeyRecommended)

		for _, issue := range cacheIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if dirtyRatio > 40 {
			report.AddRecommendation(&check.Result, "Consider lowering vm.dirty_ratio to 20-30% to prevent large I/O spikes")
		} else if dirtyRatio < 5 {
			report.AddRecommendation(&check.Result, "Consider increasing vm.dirty_ratio to 10-20% for better performance")
		}

		if vfsCachePressure > 200 {
			report.AddRecommendation(&check.Result, "Consider lowering vm.vfs_cache_pressure to 100 for better inode/dentry caching")
		}

		report.AddReferenceLink(&check.Result, sysctlDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System cache settings are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
