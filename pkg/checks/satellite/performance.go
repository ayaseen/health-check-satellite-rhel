// pkg/checks/satellite/performance.go

package satellite

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunPerformanceChecks performs Satellite performance checks
func RunPerformanceChecks(r *report.AsciiDocReport) {
	// Check system resources (CPU, memory, I/O)
	checkSystemResources(r)

	// Check tuned profile
	checkTunedProfile(r)

	// Check for service restart patterns and system errors
	checkServiceRestarts(r)

	// Check for performance bottlenecks
	checkPerformanceBottlenecks(r)

	// Check Satellite health status via maintain and API
	checkHealthStatus(r)
}

// checkHealthStatus checks Satellite health using satellite-maintain and API ping
func checkHealthStatus(r *report.AsciiDocReport) {
	checkID := "satellite-health-status"
	checkName := "Satellite Health Status"
	checkDesc := "Checks Satellite health using satellite-maintain and API ping."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Run satellite-maintain health check
	maintainCmd := "satellite-maintain health check 2>&1 || echo 'Command failed'"
	maintainOutput, _ := utils.RunCommand("bash", "-c", maintainCmd)

	// Call API ping endpoint
	apiPingCmd := "curl -ks https://$(hostname)/api/ping | python3 -m json.tool 2>/dev/null || curl -ks https://$(hostname)/api/ping | json_reformat 2>/dev/null || echo 'Failed to format JSON'"
	apiPingOutput, _ := utils.RunCommand("bash", "-c", apiPingCmd)

	// Build detail report
	var detail strings.Builder
	detail.WriteString("Satellite Health Status Check:\n\n")

	// Add satellite-maintain output
	detail.WriteString("Satellite Maintain Health Check:\n")
	detail.WriteString("[source, bash]\n----\n")
	if maintainOutput == "" {
		detail.WriteString("No output from satellite-maintain health check\n")
	} else {
		// Trim if too long
		if strings.Count(maintainOutput, "\n") > 100 {
			lines := strings.SplitN(maintainOutput, "\n", 101)
			maintainOutput = strings.Join(lines[:100], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(maintainOutput)
	}
	detail.WriteString("\n----\n\n")

	// Add API ping output
	detail.WriteString("API Ping Status:\n")
	detail.WriteString("[source, json]\n----\n")
	if apiPingOutput == "" {
		detail.WriteString("Failed to get API ping response\n")
	} else {
		detail.WriteString(apiPingOutput)
	}
	detail.WriteString("\n----\n\n")

	// Parse the outputs to determine status
	maintainHealthy := true
	apiHealthy := true
	var unhealthyServices []string
	var apiIssues []string

	// Check satellite-maintain output for any non-OK status
	if strings.Contains(maintainOutput, "**[WARNING]**") ||
		strings.Contains(maintainOutput, "**[ERROR]**") ||
		strings.Contains(maintainOutput, "[WARNING]") ||
		strings.Contains(maintainOutput, "[ERROR]") {
		maintainHealthy = false

		// Extract specific failing checks
		for _, line := range strings.Split(maintainOutput, "\n") {
			if (strings.Contains(line, "[WARNING]") || strings.Contains(line, "[ERROR]")) &&
				!strings.Contains(line, "[OK]") {
				check := strings.TrimSpace(strings.Split(line, ":")[0])
				if check != "" {
					unhealthyServices = append(unhealthyServices, check)
				}
			}
		}
	}

	// Try to parse the API ping response
	type ServiceStatus struct {
		Status     string `json:"status,omitempty"`
		Message    string `json:"message,omitempty"`
		DurationMs string `json:"duration_ms,omitempty"`
	}

	type APIResponse struct {
		Results struct {
			Foreman struct {
				Database struct {
					Active     bool   `json:"active"`
					DurationMs string `json:"duration_ms"`
				} `json:"database"`
			} `json:"foreman"`
			Katello struct {
				Services map[string]ServiceStatus `json:"services"`
				Status   string                   `json:"status"`
			} `json:"katello"`
		} `json:"results"`
	}

	var apiResp APIResponse
	if !strings.Contains(apiPingOutput, "Failed to format JSON") && apiPingOutput != "" {
		err := json.Unmarshal([]byte(apiPingOutput), &apiResp)
		if err == nil {
			// Check if any service has a non-ok status
			if apiResp.Results.Katello.Status != "ok" {
				apiHealthy = false
				apiIssues = append(apiIssues, "Katello overall status is not ok")
			}

			if !apiResp.Results.Foreman.Database.Active {
				apiHealthy = false
				apiIssues = append(apiIssues, "Foreman database is not active")
			}

			for service, status := range apiResp.Results.Katello.Services {
				if status.Status != "ok" {
					apiHealthy = false
					apiIssues = append(apiIssues, fmt.Sprintf("%s service is reporting %s", service, status.Status))
				}
			}
		} else {
			// If we couldn't parse the JSON, assume there's an issue
			apiHealthy = false
			apiIssues = append(apiIssues, "Failed to parse API response")
		}
	} else {
		apiHealthy = false
		apiIssues = append(apiIssues, "Failed to get valid API response")
	}

	// Create summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Health Status Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Component | Status | Details\n\n")

	// Satellite Maintain status
	if maintainHealthy {
		detail.WriteString("| Satellite Maintain | OK | All health checks passed\n")
	} else {
		detail.WriteString(fmt.Sprintf("| Satellite Maintain | Warning | %d issues detected\n", len(unhealthyServices)))
	}

	// API Ping status
	if apiHealthy {
		detail.WriteString("| API Ping | OK | All services reporting healthy\n")
	} else {
		detail.WriteString(fmt.Sprintf("| API Ping | Warning | %d issues detected\n", len(apiIssues)))
	}

	// Overall status
	overallStatus := "OK"
	if !maintainHealthy || !apiHealthy {
		overallStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("| Overall Health | %s | \n", overallStatus))
	detail.WriteString("|===\n\n")

	// If there are issues, list them
	if len(unhealthyServices) > 0 {
		detail.WriteString("Issues detected by satellite-maintain:\n")
		detail.WriteString("[source]\n----\n")
		for _, service := range unhealthyServices {
			detail.WriteString("- " + service + "\n")
		}
		detail.WriteString("----\n\n")
	}

	if len(apiIssues) > 0 {
		detail.WriteString("Issues detected by API ping:\n")
		detail.WriteString("[source]\n----\n")
		for _, issue := range apiIssues {
			detail.WriteString("- " + issue + "\n")
		}
		detail.WriteString("----\n")
	}

	// Evaluate results
	if !maintainHealthy && !apiHealthy {
		check.Result = report.NewResult(report.StatusWarning,
			"Multiple health checks reporting issues",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run satellite-maintain health check for detailed diagnostics")
		report.AddRecommendation(&check.Result, "Check specific services reporting issues")

		// Add specific recommendations based on detected issues
		for _, issue := range apiIssues {
			if strings.Contains(issue, "pulp") || strings.Contains(issue, "Pulp") {
				report.AddRecommendation(&check.Result, "Check Pulp services and content synchronization status")
			} else if strings.Contains(issue, "candlepin") || strings.Contains(issue, "Candlepin") {
				report.AddRecommendation(&check.Result, "Check Candlepin services and subscription status")
			} else if strings.Contains(issue, "foreman") || strings.Contains(issue, "Foreman") {
				report.AddRecommendation(&check.Result, "Check Foreman tasks and database status")
			}
		}
	} else if !maintainHealthy {
		check.Result = report.NewResult(report.StatusWarning,
			"Satellite Maintain health check reporting issues",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run satellite-maintain health check for detailed diagnostics")
		report.AddRecommendation(&check.Result, "Consider running satellite-maintain service restart")
	} else if !apiHealthy {
		check.Result = report.NewResult(report.StatusWarning,
			"API ping reporting service issues",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check specific services reporting issues")
		report.AddRecommendation(&check.Result, "Investigate application logs for errors")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All health checks reporting good status",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/tuning_performance_of_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSystemResources reviews system resource usage
func checkSystemResources(r *report.AsciiDocReport) {
	checkID := "satellite-system-resources"
	checkName := "System Resource Usage"
	checkDesc := "Reviews system resource usage (CPU, memory, I/O)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Take multiple CPU usage samples for more accurate assessment
	// Use top with 3 samples with 3 second intervals
	cpuCmd := "top -bn3 -d 3 | grep '%Cpu' | tail -3"
	cpuOutput, _ := utils.RunCommand("bash", "-c", cpuCmd)

	var detail strings.Builder
	detail.WriteString("System Resource Usage:\n\n")

	detail.WriteString("CPU Usage (Multiple Samples):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cpuOutput)
	detail.WriteString("\n----\n\n")

	// Calculate average CPU metrics across samples
	cpuIdle := 0.0
	cpuUser := 0.0
	cpuSystem := 0.0
	cpuWait := 0.0
	cpuStolen := 0.0
	sampleCount := 0

	// Process each line to extract CPU metrics
	for _, line := range strings.Split(cpuOutput, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		sampleCount++

		// Extract CPU idle percentage - first try the standard "id," format
		idlePattern := regexp.MustCompile(`(\d+\.\d+)\s+id`)
		if match := idlePattern.FindStringSubmatch(line); len(match) > 1 {
			idleVal, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				cpuIdle += idleVal
			}
		} else {
			// Try alternative format that might include "id" at the end of the line
			idleAltPattern := regexp.MustCompile(`(\d+\.\d+)\s*id`)
			if match := idleAltPattern.FindStringSubmatch(line); len(match) > 1 {
				idleVal, err := strconv.ParseFloat(match[1], 64)
				if err == nil {
					cpuIdle += idleVal
				}
			}
		}

		// Extract user CPU percentage
		userPattern := regexp.MustCompile(`(\d+\.\d+)\s+us`)
		if match := userPattern.FindStringSubmatch(line); len(match) > 1 {
			userVal, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				cpuUser += userVal
			}
		}

		// Extract system CPU percentage
		sysPattern := regexp.MustCompile(`(\d+\.\d+)\s+sy`)
		if match := sysPattern.FindStringSubmatch(line); len(match) > 1 {
			sysVal, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				cpuSystem += sysVal
			}
		}

		// Extract wait I/O percentage
		waitPattern := regexp.MustCompile(`(\d+\.\d+)\s+wa`)
		if match := waitPattern.FindStringSubmatch(line); len(match) > 1 {
			waitVal, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				cpuWait += waitVal
			}
		}

		// Extract stolen time percentage (important for VMs)
		stolenPattern := regexp.MustCompile(`(\d+\.\d+)\s+st`)
		if match := stolenPattern.FindStringSubmatch(line); len(match) > 1 {
			stolenVal, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				cpuStolen += stolenVal
			}
		}
	}

	// Calculate averages if we have samples
	if sampleCount > 0 {
		cpuIdle /= float64(sampleCount)
		cpuUser /= float64(sampleCount)
		cpuSystem /= float64(sampleCount)
		cpuWait /= float64(sampleCount)
		cpuStolen /= float64(sampleCount)
	}

	// Calculate total utilization
	cpuTotal := cpuUser + cpuSystem + cpuWait + cpuStolen

	// Add detailed CPU metrics to the report
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Detailed CPU Metrics (Average of " + strconv.Itoa(sampleCount) + " samples):\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Metric | Value\n\n")
	detail.WriteString(fmt.Sprintf("| User processes | %.1f%%\n", cpuUser))
	detail.WriteString(fmt.Sprintf("| System processes | %.1f%%\n", cpuSystem))
	detail.WriteString(fmt.Sprintf("| I/O wait | %.1f%%\n", cpuWait))
	detail.WriteString(fmt.Sprintf("| Stolen time | %.1f%%\n", cpuStolen))
	detail.WriteString(fmt.Sprintf("| Idle | %.1f%%\n", cpuIdle))
	detail.WriteString(fmt.Sprintf("| Total utilization | %.1f%%\n", cpuTotal))
	detail.WriteString("|===\n\n")

	// Get memory usage
	memCmd := "free -h"
	memOutput, _ := utils.RunCommand("bash", "-c", memCmd)

	detail.WriteString("Memory Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(memOutput)
	detail.WriteString("\n----\n\n")

	// Get detailed memory info
	memInfoCmd := "grep -E 'MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree' /proc/meminfo"
	memInfoOutput, _ := utils.RunCommand("bash", "-c", memInfoCmd)

	detail.WriteString("Memory Details:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(memInfoOutput)
	detail.WriteString("\n----\n\n")

	// Extract memory usage percentages
	memTotal := 0
	memAvailable := 0
	memUsagePercent := 0.0
	swapTotal := 0
	swapFree := 0
	swapUsagePercent := 0.0

	for _, line := range strings.Split(memInfoOutput, "\n") {
		if strings.Contains(line, "MemTotal") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				memTotal, _ = strconv.Atoi(fields[1])
			}
		} else if strings.Contains(line, "MemAvailable") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				memAvailable, _ = strconv.Atoi(fields[1])
			}
		} else if strings.Contains(line, "SwapTotal") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				swapTotal, _ = strconv.Atoi(fields[1])
			}
		} else if strings.Contains(line, "SwapFree") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				swapFree, _ = strconv.Atoi(fields[1])
			}
		}
	}

	if memTotal > 0 && memAvailable > 0 {
		memUsagePercent = 100.0 - (float64(memAvailable) / float64(memTotal) * 100.0)
	}

	if swapTotal > 0 {
		swapUsagePercent = 100.0 - (float64(swapFree) / float64(swapTotal) * 100.0)
	}

	// Check if iostat is available and get disk I/O statistics if possible
	// For more accurate disk metrics, sample over multiple iterations
	ioCmd := "command -v iostat && iostat -xz 1 3 | grep -A 20 '^Device' | grep -v '^$' || echo 'iostat command not installed'"
	ioOutput, _ := utils.RunCommand("bash", "-c", ioCmd)

	detail.WriteString("Disk I/O Statistics (Average of 3 samples):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ioOutput)
	detail.WriteString("\n----\n\n")

	// If iostat wasn't available, use alternative commands to get basic disk info
	if strings.Contains(ioOutput, "not installed") {
		// Try to get basic disk usage information
		altDiskCmd := "df -h / /var"
		altDiskOutput, _ := utils.RunCommand("bash", "-c", altDiskCmd)

		detail.WriteString("Alternative Disk Usage (iostat not available):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(altDiskOutput)
		detail.WriteString("\n----\n\n")

		// Check if any partitions are near capacity (over 85%)
		diskBottleneck := false
		highUtilization := false

		// Parse df output for high usage
		for _, line := range strings.Split(altDiskOutput, "\n") {
			if !strings.Contains(line, "Filesystem") && len(line) > 0 {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					usageStr := fields[4]
					usageStr = strings.TrimSuffix(usageStr, "%")
					usage, err := strconv.ParseFloat(usageStr, 64)
					if err == nil {
						if usage > 85 {
							diskBottleneck = true
							if usage > 95 {
								highUtilization = true
							}
						}
					}
				}
			}
		}

		// Add disk bottleneck info for later evaluation
		if diskBottleneck {
			detail.WriteString("NOTICE: High disk usage detected (>85%).\n\n")
			if highUtilization {
				detail.WriteString("WARNING: Critical disk usage detected (>95%).\n\n")
			}
		}
	}

	// Check for disk bottlenecks
	diskBottleneck := false
	highUtilization := false
	highestAvgWait := 0.0
	avgUtilSum := 0.0
	utilSamples := 0

	// Only analyze iostat output if it doesn't contain the "not installed" message
	if !strings.Contains(ioOutput, "not installed") {
		// Look for high %util in iostat output
		for _, line := range strings.Split(ioOutput, "\n") {
			if len(line) == 0 || strings.Contains(line, "Device") || !strings.Contains(line, " ") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) > 13 { // iostat -xz output usually has at least 14 fields
				utilIdx := len(fields) - 1 // Utility is typically the last field
				utilStr := fields[utilIdx]
				util, err := strconv.ParseFloat(utilStr, 64)
				if err == nil {
					utilSamples++
					avgUtilSum += util

					if util > 80.0 {
						diskBottleneck = true
						if util > 95.0 {
							highUtilization = true
						}
					}
				}

				// Also check await time
				if len(fields) > 9 {
					awaitStr := fields[9]
					await, err := strconv.ParseFloat(awaitStr, 64)
					if err == nil && await > highestAvgWait {
						highestAvgWait = await
					}
				}
			}
		}
	}

	// Calculate average disk utilization if samples exist
	avgDiskUtil := 0.0
	if utilSamples > 0 {
		avgDiskUtil = avgUtilSum / float64(utilSamples)
	}

	// Add the calculated average disk utilization
	if utilSamples > 0 {
		detail.WriteString(fmt.Sprintf("Average Disk Utilization: %.1f%%\n\n", avgDiskUtil))
	}

	// Get load average
	loadCmd := "uptime"
	loadOutput, _ := utils.RunCommand("bash", "-c", loadCmd)

	detail.WriteString("Load Average:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(loadOutput)
	detail.WriteString("\n----\n\n")

	// Extract load average
	loadPattern := regexp.MustCompile(`load average: ([\d.]+), ([\d.]+), ([\d.]+)`)
	loadMatches := loadPattern.FindStringSubmatch(loadOutput)

	// Only using load5 for evaluation; load1 and load15 not needed
	load5 := 0.0

	if len(loadMatches) > 3 {
		// Only parsing the 5-minute load average (index 2)
		load5, _ = strconv.ParseFloat(loadMatches[2], 64)
	}

	// Get CPU cores
	coresCmd := "nproc"
	coresOutput, _ := utils.RunCommand("bash", "-c", coresCmd)
	cpuCores := 1 // Default to 1 to avoid division by zero

	if coresNum, err := strconv.Atoi(strings.TrimSpace(coresOutput)); err == nil && coresNum > 0 {
		cpuCores = coresNum
	}

	loadPerCore := load5 / float64(cpuCores)

	// Get process resource usage
	processCmd := "ps aux --sort=-%mem | head -11" // Get top 10 processes by memory usage
	processOutput, _ := utils.RunCommand("bash", "-c", processCmd)

	detail.WriteString("Top Processes by Memory Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(processOutput)
	detail.WriteString("\n----\n\n")

	// Check foreman resource usage
	foremanCmd := "ps aux | grep -E '[f]oreman|[p]ulp|[h]ttpd|[p]gsql' | sort -k4,4nr | head -10"
	foremanOutput, _ := utils.RunCommand("bash", "-c", foremanCmd)

	detail.WriteString("Satellite Process Resource Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(foremanOutput)
	detail.WriteString("\n----\n")

	// Add summary of findings
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("\nResource Usage Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Metric | Value | Status\n\n")

	// Enhanced CPU status evaluation - improved with thresholds based on multiple samples
	cpuStatus := "OK"
	cpuStatusReason := ""

	// Primary concerns: high wait time or stolen time indicate resource contention
	if cpuWait > 15.0 {
		cpuStatus = "Critical"
		cpuStatusReason = "High I/O wait time indicates disk bottleneck"
	} else if cpuStolen > 20.0 {
		cpuStatus = "Critical"
		cpuStatusReason = "High stolen time indicates VM resource contention"
	} else if cpuIdle < 5.0 && cpuSystem > 40.0 {
		cpuStatus = "Critical"
		cpuStatusReason = "High system time with low idle indicates kernel bottleneck"
	} else if cpuIdle < 5.0 && cpuTotal > 95.0 {
		cpuStatus = "Warning"
		cpuStatusReason = "Very high CPU utilization"
	} else if cpuIdle < 10.0 {
		cpuStatus = "Warning"
		cpuStatusReason = "High CPU utilization"
	} else if cpuWait > 5.0 {
		cpuStatus = "Warning"
		cpuStatusReason = "Moderate I/O wait time"
	}

	// CPU Status with reason
	detail.WriteString(fmt.Sprintf("| CPU Idle | %.1f%% | %s", cpuIdle, cpuStatus))
	if cpuStatusReason != "" {
		detail.WriteString(fmt.Sprintf(" (%s)", cpuStatusReason))
	}
	detail.WriteString("\n")

	// Add CPU component breakdowns
	detail.WriteString(fmt.Sprintf("| CPU User | %.1f%% | -\n", cpuUser))
	detail.WriteString(fmt.Sprintf("| CPU System | %.1f%% | -\n", cpuSystem))
	detail.WriteString(fmt.Sprintf("| CPU I/O Wait | %.1f%% | -\n", cpuWait))
	if cpuStolen > 0 {
		detail.WriteString(fmt.Sprintf("| CPU Stolen | %.1f%% | -\n", cpuStolen))
	}

	// Memory Status
	memStatus := "OK"
	if memUsagePercent > 80.0 {
		memStatus = "Warning"
	} else if memUsagePercent > 90.0 {
		memStatus = "Critical"
	}
	detail.WriteString(fmt.Sprintf("| Memory Usage | %.1f%% | %s\n", memUsagePercent, memStatus))

	// Swap Status - add this as a separate metric
	if swapTotal > 0 {
		swapStatus := "OK"
		if swapUsagePercent > 50.0 {
			swapStatus = "Warning"
		} else if swapUsagePercent > 80.0 {
			swapStatus = "Critical"
		}
		detail.WriteString(fmt.Sprintf("| Swap Usage | %.1f%% | %s\n", swapUsagePercent, swapStatus))
	}

	// Load Status
	loadStatus := "OK"
	if loadPerCore > 1.5 {
		loadStatus = "Warning"
	} else if loadPerCore > 3.0 {
		loadStatus = "Critical"
	}
	detail.WriteString(fmt.Sprintf("| Load Average (5 min) | %.2f | %s\n", load5, loadStatus))
	detail.WriteString(fmt.Sprintf("| Load Per Core | %.2f | %s\n", loadPerCore, loadStatus))

	// Disk Status
	diskStatus := "OK"
	if diskBottleneck {
		diskStatus = "Warning"
		if highUtilization {
			diskStatus = "Critical"
		}
		detail.WriteString(fmt.Sprintf("| Disk I/O | Bottleneck detected | %s\n", diskStatus))

		// Add average disk utilization as a specific metric
		if utilSamples > 0 {
			detail.WriteString(fmt.Sprintf("| Avg Disk Utilization | %.1f%% | %s\n", avgDiskUtil, diskStatus))
		}

		// Add highest wait time as a specific metric
		detail.WriteString(fmt.Sprintf("| Highest Disk Wait | %.1f ms | %s\n", highestAvgWait, diskStatus))
	} else {
		detail.WriteString("| Disk I/O | Normal | OK\n")
	}
	detail.WriteString("|===\n")

	// Evaluate results - check for actual performance issues
	highLoad := loadPerCore > 3.0
	highMemory := memUsagePercent > 90.0
	highSwap := swapUsagePercent > 80.0 && swapTotal > 0

	// Improved CPU bottleneck detection based on multiple factors and multiple samples
	highCPUWait := cpuWait > 10.0
	highStolenTime := cpuStolen > 15.0
	highSystemTime := cpuSystem > 40.0
	lowCPUIdle := cpuIdle < 5.0

	// CPU bottleneck is determined by multiple factors
	cpuBottleneck := (lowCPUIdle && highLoad) ||
		highCPUWait ||
		highStolenTime ||
		(lowCPUIdle && highSystemTime)

	// Critical condition - multiple critical resources at once
	if (highUtilization && highLoad) || (highMemory && cpuBottleneck) {
		check.Result = report.NewResult(report.StatusCritical,
			"Critical system resource utilization detected",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Investigate high disk I/O and CPU utilization immediately")
		report.AddRecommendation(&check.Result, "Consider adding more system resources")
		report.AddRecommendation(&check.Result, "Check for specific Satellite tasks causing high load")
	} else if highUtilization && diskBottleneck {
		// Critical disk issues
		check.Result = report.NewResult(report.StatusCritical,
			"Critical disk bottleneck detected",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Investigate disk I/O bottlenecks immediately")
		report.AddRecommendation(&check.Result, "Consider faster storage or optimizing disk access patterns")
	} else if highCPUWait {
		// High I/O wait is a specific bottleneck
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High CPU I/O wait time detected (%.1f%%)", cpuWait),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check for disk bottlenecks affecting CPU performance")
		report.AddRecommendation(&check.Result, "Consider upgrading storage subsystem or optimizing I/O patterns")
	} else if highStolenTime {
		// High stolen time indicates VM contention
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High CPU stolen time detected (%.1f%%)", cpuStolen),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "VM is experiencing resource contention on the hypervisor")
		report.AddRecommendation(&check.Result, "Consider requesting more dedicated resources or moving to a less contended host")
	} else if highLoad {
		// High system load but other resources OK
		check.Result = report.NewResult(report.StatusWarning,
			"High system load detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "High CPU load detected, consider adding more CPU cores")
	} else if highMemory {
		// High memory usage but other resources OK
		check.Result = report.NewResult(report.StatusWarning,
			"High memory utilization detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Memory usage is very high, consider adding more RAM")
	} else if highSwap {
		// High swap usage indicates memory pressure
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High swap utilization detected (%.1f%%)", swapUsagePercent),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "System is using significant swap space, indicating memory pressure")
		report.AddRecommendation(&check.Result, "Consider adding more RAM or optimizing memory usage")
	} else if diskBottleneck {
		// Disk bottlenecks but other resources OK
		check.Result = report.NewResult(report.StatusWarning,
			"Disk bottleneck detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate disk I/O bottlenecks")
		report.AddRecommendation(&check.Result, "Consider faster storage or optimizing disk access patterns")
	} else if cpuBottleneck {
		// CPU bottleneck based on improved detection
		check.Result = report.NewResult(report.StatusWarning,
			"CPU bottleneck detected",
			report.ResultKeyAdvisory)
		if lowCPUIdle && highSystemTime {
			report.AddRecommendation(&check.Result, "High system CPU usage may indicate kernel or I/O issues")
		} else {
			report.AddRecommendation(&check.Result, "Monitor CPU utilization for sustained periods of high usage")
		}
	} else if lowCPUIdle && memUsagePercent < 60.0 && loadPerCore < 0.7 {
		// Low CPU idle but memory and load are good - likely normal operation
		check.Result = report.NewResult(report.StatusOK,
			"System appears to be processing efficiently",
			report.ResultKeyNoChange)
	} else if loadPerCore > 1.5 || memUsagePercent > 80.0 {
		// Moderate utilization
		check.Result = report.NewResult(report.StatusWarning,
			"Moderate system resource utilization detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor system resources for upward trends")
	} else {
		// Everything normal
		check.Result = report.NewResult(report.StatusOK,
			"System resource utilization appears normal",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/tuning_performance_of_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkTunedProfile ensures tuned profile is set appropriately
func checkTunedProfile(r *report.AsciiDocReport) {
	checkID := "satellite-tuned-profile"
	checkName := "Tuned Profile"
	checkDesc := "Ensures tuned profile is set to 'throughput-performance' or similar."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check active tuned profile
	tunedCmd := "tuned-adm active"
	tunedOutput, err := utils.RunCommand("bash", "-c", tunedCmd)

	var detail strings.Builder
	detail.WriteString("Tuned Profile Configuration:\n\n")

	if err != nil {
		detail.WriteString("Error getting tuned profile or tuned-adm not installed:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		// Try to check if tuned is installed
		checkTunedCmd := "rpm -q tuned || echo 'tuned not installed'"
		checkTunedOutput, _ := utils.RunCommand("bash", "-c", checkTunedCmd)
		detail.WriteString("Tuned package status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(checkTunedOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("Active Tuned Profile:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(tunedOutput)
		detail.WriteString("\n----\n\n")
	}

	// List available profiles
	profilesCmd := "tuned-adm list"
	profilesOutput, _ := utils.RunCommand("bash", "-c", profilesCmd)

	detail.WriteString("Available Profiles:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(profilesOutput)
	detail.WriteString("\n----\n\n")

	// Check tuned service status
	statusCmd := "systemctl status tuned"
	statusOutput, _ := utils.RunCommand("bash", "-c", statusCmd)

	detail.WriteString("Tuned Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(statusOutput)
	detail.WriteString("\n----\n\n")

	// Get system type to determine appropriate profile
	systemTypeCmd := "lscpu | grep Hypervisor"
	systemTypeOutput, _ := utils.RunCommand("bash", "-c", systemTypeCmd)

	isVirtual := systemTypeOutput != ""

	// If first method fails, try alternative
	if !isVirtual {
		altVirtualCheckCmd := "systemd-detect-virt || echo 'none'"
		altVirtualCheckOutput, _ := utils.RunCommand("bash", "-c", altVirtualCheckCmd)
		isVirtual = altVirtualCheckOutput != "" && !strings.Contains(altVirtualCheckOutput, "none")
	}

	detail.WriteString("System Type:\n")
	detail.WriteString("[source, bash]\n----\n")
	if isVirtual {
		detail.WriteString("Virtual Machine\n")
	} else {
		detail.WriteString("Physical Machine\n")
	}
	detail.WriteString("\n----\n\n")

	// Determine recommended profile based on system type
	recommendedProfile := "throughput-performance"
	if isVirtual {
		recommendedProfile = "virtual-guest"
	}

	// Check if current profile is appropriate
	currentProfile := ""
	if strings.Contains(tunedOutput, "Current active profile:") {
		profileParts := strings.Split(tunedOutput, ":")
		if len(profileParts) > 1 {
			currentProfile = strings.TrimSpace(profileParts[1])
		}
	}

	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Profile Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Configuration | Value\n\n")
	detail.WriteString(fmt.Sprintf("| Recommended Profile | %s\n", recommendedProfile))
	detail.WriteString(fmt.Sprintf("| Current Profile | %s\n", currentProfile))
	detail.WriteString("|===\n")

	// Check if tuned is installed and running
	tunedInstalled := !strings.Contains(statusOutput, "not-found") && !strings.Contains(statusOutput, "could not be found")
	tunedRunning := strings.Contains(statusOutput, "Active: active (running)")

	// Evaluate results
	if !tunedInstalled {
		check.Result = report.NewResult(report.StatusWarning,
			"tuned package is not installed",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install tuned: foreman-maintain packages install -y tuned")
		report.AddRecommendation(&check.Result, fmt.Sprintf("Set tuned profile to %s", recommendedProfile))
	} else if !tunedRunning {
		check.Result = report.NewResult(report.StatusWarning,
			"tuned service is not running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start tuned service: systemctl start tuned")
		report.AddRecommendation(&check.Result, "Enable tuned service: systemctl enable tuned")
		report.AddRecommendation(&check.Result, fmt.Sprintf("Set tuned profile to %s: tuned-adm profile %s", recommendedProfile, recommendedProfile))
	} else if currentProfile == "" {
		check.Result = report.NewResult(report.StatusWarning,
			"No tuned profile is active",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Set tuned profile to %s", recommendedProfile))
		report.AddRecommendation(&check.Result, fmt.Sprintf("Run: tuned-adm profile %s", recommendedProfile))
	} else if currentProfile != recommendedProfile &&
		!(recommendedProfile == "throughput-performance" && currentProfile == "latency-performance") &&
		!(recommendedProfile == "virtual-guest" && currentProfile == "virtual-host") {

		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Current tuned profile (%s) is not optimal", currentProfile),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Set tuned profile to %s", recommendedProfile))
		report.AddRecommendation(&check.Result, fmt.Sprintf("Run: tuned-adm profile %s", recommendedProfile))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Tuned profile is appropriately configured",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/tuning_performance_of_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkServiceRestarts checks for service restart patterns or system errors
func checkServiceRestarts(r *report.AsciiDocReport) {
	checkID := "satellite-service-restarts"
	checkName := "Service Restart Patterns"
	checkDesc := "Checks for service restart patterns or system errors."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check for service restarts in journal
	journalCmd := "journalctl -u foreman -u httpd -u postgresql -u pulp* -u qdrouterd -u qpidd -u dynflow* --since '1 week ago' | grep -i 'starting\\|started\\|stopped\\|stopping\\|restarting' | tail -100"
	journalOutput, _ := utils.RunCommand("bash", "-c", journalCmd)

	var detail strings.Builder
	detail.WriteString("Service Restart Patterns:\n\n")

	detail.WriteString("Recent Service Events:\n")
	detail.WriteString("[source, bash]\n----\n")
	if journalOutput == "" {
		detail.WriteString("No service restart events found in the last week\n")
	} else {
		// Trim if too long
		if strings.Count(journalOutput, "\n") > 50 {
			lines := strings.SplitN(journalOutput, "\n", 51)
			journalOutput = strings.Join(lines[:50], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(journalOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check system errors in journal
	errorsCmd := "journalctl -p err -p emerg -p crit -p alert --since '2 days ago' | grep -v 'audispd' | tail -100"
	errorsOutput, _ := utils.RunCommand("bash", "-c", errorsCmd)

	detail.WriteString("System Errors (Last 2 Days):\n")
	detail.WriteString("[source, bash]\n----\n")
	if errorsOutput == "" {
		detail.WriteString("No critical system errors found\n")
	} else {
		// Trim if too long
		if strings.Count(errorsOutput, "\n") > 30 {
			lines := strings.SplitN(errorsOutput, "\n", 31)
			errorsOutput = strings.Join(lines[:30], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(errorsOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check Satellite specific logs for errors
	satelliteLogsCmd := "grep -i 'error\\|exception\\|fail' /var/log/foreman/production.log /var/log/httpd/error_log /var/log/candlepin/candlepin.log 2>/dev/null | tail -100"
	satelliteLogsOutput, _ := utils.RunCommand("bash", "-c", satelliteLogsCmd)

	detail.WriteString("Satellite Log Errors:\n")
	detail.WriteString("[source, bash]\n----\n")
	if satelliteLogsOutput == "" {
		detail.WriteString("No significant errors found in Satellite logs\n")
	} else {
		// Trim if too long
		if strings.Count(satelliteLogsOutput, "\n") > 30 {
			lines := strings.SplitN(satelliteLogsOutput, "\n", 31)
			satelliteLogsOutput = strings.Join(lines[:30], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(satelliteLogsOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check OOM events
	oomCmd := "journalctl -k --since '1 week ago' | grep -i 'out of memory\\|oom'"
	oomOutput, _ := utils.RunCommand("bash", "-c", oomCmd)

	detail.WriteString("Out of Memory Events:\n")
	detail.WriteString("[source, bash]\n----\n")
	if oomOutput == "" {
		detail.WriteString("No Out of Memory events found\n")
	} else {
		detail.WriteString(oomOutput)
	}
	detail.WriteString("\n----\n\n")

	// Count restarts and errors
	restartCount := 0
	if journalOutput != "" {
		lines := strings.Split(journalOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "starting") || strings.Contains(line, "Started") ||
				strings.Contains(line, "restarting") {
				restartCount++
			}
		}
	}

	// Count error events
	errorCount := 0
	if errorsOutput != "" {
		errorCount = len(strings.Split(errorsOutput, "\n"))
	}

	// Count OOM events
	oomCount := 0
	if oomOutput != "" {
		oomCount = len(strings.Split(oomOutput, "\n"))
	}

	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Event Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Event Type | Count | Status\n\n")

	restartStatus := "OK"
	if restartCount > 10 {
		restartStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("| Service restart events | %d | %s\n", restartCount, restartStatus))

	errorStatus := "OK"
	if errorCount > 20 {
		errorStatus = "Warning"
	}
	detail.WriteString(fmt.Sprintf("| System error events | %d | %s\n", errorCount, errorStatus))

	oomStatus := "OK"
	if oomCount > 0 {
		oomStatus = "Critical"
	}
	detail.WriteString(fmt.Sprintf("| Out of Memory events | %d | %s\n", oomCount, oomStatus))
	detail.WriteString("|===\n")

	// Evaluate results
	if oomCount > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("System has experienced %d Out of Memory events", oomCount),
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Increase system memory")
		report.AddRecommendation(&check.Result, "Adjust application memory limits in /etc/sysconfig/foreman")
		report.AddRecommendation(&check.Result, "Check for memory leaks in long-running processes")
	} else if restartCount > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of service restarts detected (%d)", restartCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate service stability issues")
		report.AddRecommendation(&check.Result, "Check application logs for recurring errors")
	} else if errorCount > 20 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of system errors detected (%d)", errorCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review system error logs")
		report.AddRecommendation(&check.Result, "Check for hardware or filesystem issues")
	} else if restartCount > 0 || errorCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Detected %d service restarts and %d system errors", restartCount, errorCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor service stability")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant service restart patterns or system errors detected",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPerformanceBottlenecks checks for specific performance bottlenecks
func checkPerformanceBottlenecks(r *report.AsciiDocReport) {
	checkID := "satellite-performance-bottlenecks"
	checkName := "Performance Bottlenecks"
	checkDesc := "Checks for specific performance bottlenecks in Satellite."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check Passenger performance (for Satellite 6.x)
	passengerCmd := "passenger-status 2>/dev/null || echo 'Passenger not available'"
	passengerOutput, _ := utils.RunCommand("bash", "-c", passengerCmd)

	var detail strings.Builder
	detail.WriteString("Performance Bottleneck Analysis:\n\n")

	if !strings.Contains(passengerOutput, "Passenger not available") {
		detail.WriteString("Passenger Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(passengerOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Puma status (for newer Satellite versions)
	pumaCmd := "systemctl status foreman"
	pumaOutput, _ := utils.RunCommand("bash", "-c", pumaCmd)

	detail.WriteString("Foreman Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pumaOutput)
	detail.WriteString("\n----\n\n")

	// Enhanced Dynflow check for Sidekiq workers
	dynflowWorkerCmd := "systemctl -a | grep 'dynflow-sidekiq@worker-[0-9]' | grep running | wc -l"
	dynflowWorkersCount, _ := utils.RunCommand("bash", "-c", dynflowWorkerCmd)
	dynflowWorkersCount = strings.TrimSpace(dynflowWorkersCount)

	// Get the number of Sidekiq workers from the installer configuration
	dynflowConfigCmd := "grep -E 'dynflow[_-]worker[_-]instances' /etc/foreman-installer/scenarios.d/satellite-answers.yaml || grep -E 'dynflow[_-]worker[_-]instances' /etc/foreman-installer/scenarios.d/satellite.yaml || echo 'Not configured'"
	dynflowConfigOutput, _ := utils.RunCommand("bash", "-c", dynflowConfigCmd)

	// Check for worker concurrency setting
	dynflowConcurrencyCmd := "grep -E 'dynflow[_-]worker[_-]concurrency' /etc/foreman-installer/scenarios.d/satellite-answers.yaml || grep -E 'dynflow[_-]worker[_-]concurrency' /etc/foreman-installer/scenarios.d/satellite.yaml || echo 'Not configured'"
	dynflowConcurrencyOutput, _ := utils.RunCommand("bash", "-c", dynflowConcurrencyCmd)

	// Check for worker queue files
	dynflowQueueCmd := "ls -la /etc/foreman/dynflow/ 2>/dev/null || echo 'Directory not found'"
	dynflowQueueOutput, _ := utils.RunCommand("bash", "-c", dynflowQueueCmd)

	// Get the tasks status to check for queued tasks
	tasksQueueCmd := "hammer --no-headers --csv task list --search 'state = running OR state = pending' 2>/dev/null | wc -l || echo '0'"
	pendingTasksCount, _ := utils.RunCommand("bash", "-c", tasksQueueCmd)
	pendingTasksCount = strings.TrimSpace(pendingTasksCount)

	detail.WriteString("Dynflow Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString("Active Dynflow workers: " + dynflowWorkersCount + "\n")
	detail.WriteString("\nWorker instances configuration:\n" + dynflowConfigOutput + "\n")
	detail.WriteString("\nWorker concurrency configuration:\n" + dynflowConcurrencyOutput + "\n")
	detail.WriteString("\nDynflow queue files:\n" + dynflowQueueOutput + "\n")
	detail.WriteString("\nPending/Running tasks: " + pendingTasksCount + "\n")
	detail.WriteString("\n----\n\n")

	// Check Apache connections
	apacheCmd := "systemctl status httpd"
	apacheOutput, _ := utils.RunCommand("bash", "-c", apacheCmd)

	detail.WriteString("Apache Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(apacheOutput)
	detail.WriteString("\n----\n\n")

	// Check Pulp workers
	pulpWorkersCmd := "systemctl status pulpcore* | grep 'Active: active'"
	pulpWorkersOutput, _ := utils.RunCommand("bash", "-c", pulpWorkersCmd)

	detail.WriteString("Pulp Workers Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	if pulpWorkersOutput == "" {
		detail.WriteString("No active Pulp workers found\n")
	} else {
		detail.WriteString(pulpWorkersOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check for slow queries
	slowQueriesCmd := "grep -i 'slow query' /var/log/foreman/production.log /var/log/messages 2>/dev/null | tail -20"
	slowQueriesOutput, _ := utils.RunCommand("bash", "-c", slowQueriesCmd)

	detail.WriteString("Slow Query Logs:\n")
	detail.WriteString("[source, bash]\n----\n")
	if slowQueriesOutput == "" {
		detail.WriteString("No slow queries found in logs\n")
	} else {
		detail.WriteString(slowQueriesOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check for Ruby garbage collection issues
	gcCmd := "grep -i 'gc' /var/log/foreman/production.log 2>/dev/null | grep -i 'memory\\|allocation\\|heap' | tail -20"
	gcOutput, _ := utils.RunCommand("bash", "-c", gcCmd)

	detail.WriteString("Ruby GC Log Entries:\n")
	detail.WriteString("[source, bash]\n----\n")
	if gcOutput == "" {
		detail.WriteString("No significant GC entries found\n")
	} else {
		detail.WriteString(gcOutput)
	}
	detail.WriteString("\n----\n\n")

	// Try to check for disk latency with different tools
	// First try iostat
	detail.WriteString("Disk Latency Check:\n")
	detail.WriteString("[source, bash]\n----\n")

	diskLatencyOutput := ""
	diskLatencyCmd := "command -v iostat && iostat -d -x 1 5 | grep -v '^$' | grep -v 'Device' || echo 'iostat not available'"
	diskLatencyOutput, _ = utils.RunCommand("bash", "-c", diskLatencyCmd)

	if strings.Contains(diskLatencyOutput, "not available") {
		// Try alternative disk latency check with 'dd' if iostat is not available
		altDiskCmd := "dd if=/dev/zero of=/tmp/disktest bs=1M count=100 oflag=direct 2>&1 && rm /tmp/disktest"
		altDiskOutput, _ := utils.RunCommand("bash", "-c", altDiskCmd)
		detail.WriteString("Disk latency check (using dd):\n")
		detail.WriteString(altDiskOutput)
		detail.WriteString("\n")
	} else {
		detail.WriteString(diskLatencyOutput)
	}
	detail.WriteString("\n----\n")

	// Parse results to find bottlenecks
	passengerBottleneck := false
	if !strings.Contains(passengerOutput, "Passenger not available") {
		// Check for Passenger queue
		if strings.Contains(passengerOutput, "Requests in queue:") {
			for _, line := range strings.Split(passengerOutput, "\n") {
				if strings.Contains(line, "Requests in queue:") {
					queueStr := strings.TrimSpace(strings.Split(line, ":")[1])
					queueSize, _ := strconv.Atoi(queueStr)
					if queueSize > 0 {
						passengerBottleneck = true
						break
					}
				}
			}
		}
	}

	// Check for disk latency issues
	diskLatencyIssue := false
	highestAvgWait := 0.0

	// Only analyze iostat output if it's available
	if !strings.Contains(diskLatencyOutput, "not available") {
		for _, line := range strings.Split(diskLatencyOutput, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 10 { // iostat -d -x format
				avgWaitIdx := 9 // Usually w_await is at index 9
				if len(fields) > avgWaitIdx {
					avgWaitStr := fields[avgWaitIdx] // avg wait time (w_await)
					avgWait, err := strconv.ParseFloat(avgWaitStr, 64)
					if err == nil && avgWait > 10.0 { // Over 10ms is concerning
						diskLatencyIssue = true
						if avgWait > highestAvgWait {
							highestAvgWait = avgWait
						}
					}
				}
			}
		}
	}

	// Check for slow queries
	slowQueriesIssue := slowQueriesOutput != "" && !strings.Contains(slowQueriesOutput, "No slow queries")

	// Prepare Dynflow status for the bottleneck summary
	workersInt, err := strconv.Atoi(dynflowWorkersCount)
	if err != nil {
		workersInt = 0
	}
	pendingTasksInt, err := strconv.Atoi(pendingTasksCount)
	if err != nil {
		pendingTasksInt = 0
	}

	// Determine Dynflow status
	dynflowStatus := "OK"
	dynflowDetails := ""
	dynflowBottleneck := false

	if workersInt <= 1 {
		dynflowStatus = "Warning"
		dynflowDetails = fmt.Sprintf("Only %s Dynflow worker detected", dynflowWorkersCount)
		dynflowBottleneck = true
	} else if workersInt < 3 && pendingTasksInt > 10 {
		dynflowStatus = "Warning"
		dynflowDetails = fmt.Sprintf("%d workers with %s pending tasks", workersInt, pendingTasksCount)
		dynflowBottleneck = true
	} else {
		dynflowDetails = fmt.Sprintf("%d workers active", workersInt)
	}

	// Add bottleneck summary
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("\nBottleneck Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Component | Status | Details\n\n")

	// Passenger status
	if passengerBottleneck {
		detail.WriteString("| Passenger | Warning | Request queue present\n")
	} else if !strings.Contains(passengerOutput, "Passenger not available") {
		detail.WriteString("| Passenger | OK | No queued requests\n")
	} else {
		detail.WriteString("| Passenger | N/A | Not installed or available\n")
	}

	// Disk latency status
	if diskLatencyIssue {
		if highestAvgWait > 20.0 {
			detail.WriteString(fmt.Sprintf("| Disk Latency | Critical | %.1f ms average wait time\n", highestAvgWait))
		} else {
			detail.WriteString(fmt.Sprintf("| Disk Latency | Warning | %.1f ms average wait time\n", highestAvgWait))
		}
	} else if strings.Contains(diskLatencyOutput, "not available") {
		detail.WriteString("| Disk Latency | Unknown | Could not test with iostat\n")
	} else {
		detail.WriteString("| Disk Latency | OK | No significant latency issues\n")
	}

	// Dynflow workers status
	detail.WriteString(fmt.Sprintf("| Dynflow Workers | %s | %s\n", dynflowStatus, dynflowDetails))

	// Database status
	if slowQueriesIssue {
		detail.WriteString("| Database | Warning | Slow queries detected\n")
	} else {
		detail.WriteString("| Database | OK | No slow queries detected\n")
	}

	// Add GC issues
	if gcOutput != "" && !strings.Contains(gcOutput, "No significant GC entries") {
		detail.WriteString("| Ruby GC | Warning | GC issues in logs\n")
	} else {
		detail.WriteString("| Ruby GC | OK | No significant GC issues\n")
	}
	detail.WriteString("|===\n")

	// Evaluate results
	if passengerBottleneck && diskLatencyIssue {
		check.Result = report.NewResult(report.StatusWarning,
			"Multiple performance bottlenecks detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Passenger has request queue - increase worker processes")
		report.AddRecommendation(&check.Result, fmt.Sprintf("High disk latency (%.1f ms) - improve storage performance", highestAvgWait))
	} else if diskLatencyIssue && highestAvgWait > 20.0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High disk latency (%.1f ms) detected", highestAvgWait),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Improve storage subsystem performance")
		report.AddRecommendation(&check.Result, "Consider SSD storage for database and Pulp content")
	} else if dynflowBottleneck {
		check.Result = report.NewResult(report.StatusWarning,
			"Dynflow worker configuration may be insufficient for workload",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Increase the number of Dynflow worker instances: satellite-installer --foreman-dynflow-worker-instances 3")
		report.AddRecommendation(&check.Result, "Optionally set worker concurrency: --foreman-dynflow-worker-concurrency 5")
		report.AddRecommendation(&check.Result, "Check status with: systemctl -a | grep dynflow-sidekiq@worker")
	} else if passengerBottleneck {
		check.Result = report.NewResult(report.StatusWarning,
			"Passenger request queue indicates web tier bottleneck",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Increase Passenger worker processes")
		report.AddRecommendation(&check.Result, "Check for slow requests in application logs")
	} else if slowQueriesIssue {
		check.Result = report.NewResult(report.StatusWarning,
			"Slow database queries detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Optimize database queries")
		report.AddRecommendation(&check.Result, "Check database configuration and indexes")
	} else if diskLatencyIssue {
		check.Result = report.NewResult(report.StatusWarning,
			"Moderate disk latency issues detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor disk performance")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant performance bottlenecks detected",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/tuning_performance_of_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
