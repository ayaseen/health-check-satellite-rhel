// pkg/checks/rhel/cpu.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunCPUChecks performs CPU-related checks
func RunCPUChecks(r *report.AsciiDocReport) {
	// Check CPU count, architecture, and utilization
	checkCPUInfo(r)

	// Check tuned profile
	checkTunedProfile(r)

	// Check for CPU bottlenecks
	checkCPUBottlenecks(r)
}

// checkCPUInfo checks CPU count, architecture, and utilization trends
func checkCPUInfo(r *report.AsciiDocReport) {
	checkID := "cpu-info"
	checkName := "CPU Information"
	checkDesc := "Reviews CPU count, architecture, and utilization trends."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get CPU information
	cpuInfoCmd := "lscpu"
	cpuInfoOutput, err := utils.RunCommand("bash", "-c", cpuInfoCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine CPU information", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'lscpu' command is available.")
		r.AddCheck(check)
		return
	}

	// Get number of CPUs/cores from /proc/cpuinfo
	cpuCountCmd := "grep -c processor /proc/cpuinfo"
	cpuCountOutput, _ := utils.RunCommand("bash", "-c", cpuCountCmd)
	cpuCount := strings.TrimSpace(cpuCountOutput)

	// Get CPU utilization from top
	topCmd := "top -bn1 | grep '%Cpu'"
	topOutput, _ := utils.RunCommand("bash", "-c", topCmd)

	// Get CPU load averages
	loadAvgCmd := "cat /proc/loadavg"
	loadAvgOutput, _ := utils.RunCommand("bash", "-c", loadAvgCmd)
	loadAvg := strings.TrimSpace(loadAvgOutput)

	var detail strings.Builder
	detail.WriteString("CPU Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cpuInfoOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nCPU Count: ")
	detail.WriteString(cpuCount)

	detail.WriteString("\n\nCPU Utilization:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(topOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nLoad Average: ")
	detail.WriteString(loadAvg)

	// Extract key CPU information
	cpuModel := "Unknown"
	cpuCores := 0
	cpuFrequency := "Unknown"

	for _, line := range strings.Split(cpuInfoOutput, "\n") {
		if strings.HasPrefix(line, "Model name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpuModel = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "CPU MHz:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpuFrequency = strings.TrimSpace(parts[1]) + " MHz"
			}
		} else if strings.HasPrefix(line, "CPU(s):") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cpuCountStr := strings.TrimSpace(parts[1])
				cpuCores, _ = strconv.Atoi(cpuCountStr)
			}
		}
	}

	// Parse load average
	loadValues := strings.Fields(loadAvg)
	load1 := 0.0
	if len(loadValues) > 0 {
		load1, _ = strconv.ParseFloat(loadValues[0], 64)
	}

	// Check for CPU issues
	cpuIssues := []string{}
	if cpuCores < 2 {
		cpuIssues = append(cpuIssues, "System has very low CPU count (less than 2 cores)")
	}

	// Check if load is high relative to CPU count
	if cpuCores > 0 && load1 > float64(cpuCores)*0.8 {
		cpuIssues = append(cpuIssues, fmt.Sprintf("High CPU load (%.2f) relative to core count (%d)", load1, cpuCores))
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate CPU configuration
	if len(cpuIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d CPU configuration or utilization issues", len(cpuIssues)),
			report.ResultKeyRecommended)

		for _, issue := range cpuIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if cpuCores < 2 {
			report.AddRecommendation(&check.Result, "Consider allocating more CPU cores if this is a virtual machine")
		}

		if cpuCores > 0 && load1 > float64(cpuCores)*0.8 {
			report.AddRecommendation(&check.Result, "Investigate high CPU load with 'top' and 'ps'")
			report.AddRecommendation(&check.Result, "Consider optimizing workloads or adding CPU resources")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/monitoring-cpu-usage-using-performance-co-pilot_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("System has %d CPU cores (%s, %s) with normal utilization",
				cpuCores, cpuModel, cpuFrequency),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkTunedProfile verifies system is using an appropriate tuned profile
func checkTunedProfile(r *report.AsciiDocReport) {
	checkID := "tuned-profile"
	checkName := "Tuned Profile"
	checkDesc := "Verifies system is using an appropriate tuned profile."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if tuned is installed
	_, tunedInstallErr := utils.RunCommand("rpm", "-q", "tuned")

	// Get active tuned profile
	tunedActiveCmd := "tuned-adm active"
	tunedActiveOutput, tunedActiveErr := utils.RunCommand("bash", "-c", tunedActiveCmd)
	activeProfile := "None"

	if tunedActiveErr == nil {
		for _, line := range strings.Split(tunedActiveOutput, "\n") {
			if strings.Contains(line, "Current active profile:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					activeProfile = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}

	// Get list of available profiles
	tunedListCmd := "tuned-adm list"
	tunedListOutput, _ := utils.RunCommand("bash", "-c", tunedListCmd)

	// Determine the system type to suggest the appropriate profile
	// Check if this is a virtual machine
	virt := "physical"
	virtCheckCmd := "systemd-detect-virt || echo 'physical'"
	virtOutput, _ := utils.RunCommand("bash", "-c", virtCheckCmd)

	if !strings.Contains(virtOutput, "physical") && strings.TrimSpace(virtOutput) != "" {
		virt = strings.TrimSpace(virtOutput)
	}

	// Check if this is a server or desktop
	isServer := true // Default assumption for RHEL

	// Additional check for GNOME desktop
	desktopCheckCmd := "rpm -q gnome-desktop3 2>/dev/null || echo 'not installed'"
	desktopOutput, _ := utils.RunCommand("bash", "-c", desktopCheckCmd)
	if !strings.Contains(desktopOutput, "not installed") {
		isServer = false
	}

	var detail strings.Builder
	if tunedInstallErr != nil {
		detail.WriteString("Tuned is not installed\n")
	} else {
		detail.WriteString(fmt.Sprintf("Active Tuned Profile: %s\n\n", activeProfile))
		detail.WriteString("Available Profiles:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(tunedListOutput)
		detail.WriteString("\n----\n")
	}

	detail.WriteString(fmt.Sprintf("\nSystem Type: %s\n", virt))
	detail.WriteString(fmt.Sprintf("Server Role: %v\n", isServer))

	// Determine recommended profile
	recommendedProfile := "throughput-performance"

	if virt != "physical" {
		// For virtual machines
		recommendedProfile = "virtual-guest"
	} else if !isServer {
		// For desktop systems
		recommendedProfile = "balanced"
	}

	// Check for specialized workloads
	// Database server check
	dbCheckCmd := "rpm -qa | grep -E '(mysql|mariadb|postgresql|oracle)'"
	dbOutput, _ := utils.RunCommand("bash", "-c", dbCheckCmd)
	if strings.TrimSpace(dbOutput) != "" {
		recommendedProfile = "latency-performance"
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate tuned profile
	if tunedInstallErr != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Tuned is not installed",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install tuned: 'yum install tuned'")
		report.AddRecommendation(&check.Result, "Enable and start tuned: 'systemctl enable --now tuned'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/getting-started-with-tuned_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else if activeProfile == "None" || activeProfile == "" {
		check.Result = report.NewResult(report.StatusWarning,
			"No tuned profile is active",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Activate recommended profile: 'tuned-adm profile %s'", recommendedProfile))

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/tuned-profiles-distributed-with-rhel_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else if activeProfile != recommendedProfile {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Current tuned profile (%s) may not be optimal", activeProfile),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Consider changing to recommended profile: 'tuned-adm profile %s'", recommendedProfile))
		report.AddRecommendation(&check.Result, "Review workload requirements before changing profiles")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/tuned-profiles-distributed-with-rhel_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Appropriate tuned profile (%s) is active", activeProfile),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkCPUBottlenecks identifies CPU bottlenecks or misconfigured services
func checkCPUBottlenecks(r *report.AsciiDocReport) {
	checkID := "cpu-bottlenecks"
	checkName := "CPU Bottlenecks"
	checkDesc := "Identifies any CPU bottlenecks or misconfigured services."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get top CPU consuming processes
	topProcessesCmd := "ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -11"
	topProcessesOutput, err := utils.RunCommand("bash", "-c", topProcessesCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine CPU utilization by process", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'ps' command is available.")
		r.AddCheck(check)
		return
	}

	// Get CPU statistics
	cpuStatsCmd := "mpstat -P ALL 1 3"
	cpuStatsOutput, _ := utils.RunCommand("bash", "-c", cpuStatsCmd)

	if strings.Contains(cpuStatsOutput, "command not found") {
		cpuStatsCmd = "vmstat 1 3"
		cpuStatsOutput, _ = utils.RunCommand("bash", "-c", cpuStatsCmd)
	}

	// Get interrupt information
	interruptCmd := "cat /proc/interrupts | head -20"
	interruptOutput, _ := utils.RunCommand("bash", "-c", interruptCmd)

	var detail strings.Builder
	detail.WriteString("Top CPU Consuming Processes:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(topProcessesOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nCPU Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cpuStatsOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nInterrupt Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(interruptOutput)
	detail.WriteString("\n----\n")

	// Check for high CPU usage processes
	cpuIssues := []string{}
	processLines := strings.Split(topProcessesOutput, "\n")

	// Skip header line
	if len(processLines) > 1 {
		processLines = processLines[1:]
	}

	for _, line := range processLines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			cpuUsageStr := fields[len(fields)-2]
			cpuUsage, err := strconv.ParseFloat(cpuUsageStr, 64)
			if err == nil && cpuUsage > 80.0 {
				// Get the command name (which could have spaces)
				cmd := "Unknown"
				if len(fields) >= 3 {
					cmdFields := fields[:len(fields)-2]
					if len(cmdFields) > 2 {
						cmd = strings.Join(cmdFields[2:], " ")
					}
				}
				cpuIssues = append(cpuIssues, fmt.Sprintf("Process using %.1f%% CPU: %s", cpuUsage, cmd))
			}
		}
	}

	// Check for CPU load imbalance
	cpuImbalance := false
	if strings.Contains(cpuStatsOutput, "CPU") {
		// This is a rough check - in a real implementation we would parse and analyze the stats more carefully
		maxCPU := 0.0
		minCPU := 100.0
		cpuValues := []float64{}

		// Extract CPU idle values from mpstat output
		for _, line := range strings.Split(cpuStatsOutput, "\n") {
			if strings.Contains(line, "all") || strings.Contains(line, "Average") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) > 6 {
				idleStr := fields[len(fields)-1]
				idle, err := strconv.ParseFloat(idleStr, 64)
				if err == nil {
					usage := 100.0 - idle
					cpuValues = append(cpuValues, usage)
					if usage > maxCPU {
						maxCPU = usage
					}
					if usage < minCPU {
						minCPU = usage
					}
				}
			}
		}

		// Check if we have a significant imbalance (more than 30% difference)
		if len(cpuValues) > 1 && (maxCPU-minCPU) > 30.0 {
			cpuImbalance = true
			cpuIssues = append(cpuIssues, fmt.Sprintf("CPU load imbalance detected (max: %.1f%%, min: %.1f%%)", maxCPU, minCPU))
		}
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate CPU bottlenecks
	if len(cpuIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d potential CPU bottlenecks", len(cpuIssues)),
			report.ResultKeyRecommended)

		for _, issue := range cpuIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Use 'top' and 'ps' to investigate high-CPU processes")

		if cpuImbalance {
			report.AddRecommendation(&check.Result, "Consider reviewing CPU affinity settings for critical processes")
			report.AddRecommendation(&check.Result, "Check for processes pinned to specific CPUs")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/monitoring-cpu-usage-using-performance-co-pilot_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No CPU bottlenecks detected",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
