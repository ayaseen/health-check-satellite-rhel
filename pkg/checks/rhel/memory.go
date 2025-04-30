// pkg/checks/rhel/memory.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunMemoryChecks performs memory and swap related checks
func RunMemoryChecks(r *report.AsciiDocReport) {
	// Physical memory check
	checkPhysicalMemory(r)

	// Swap configuration check
	checkSwapConfiguration(r)

	// VM tuning parameters check
	checkVMTuningParameters(r)
}

// checkPhysicalMemory validates total physical memory and usage levels
func checkPhysicalMemory(r *report.AsciiDocReport) {
	checkID := "memory-physical"
	checkName := "Physical Memory"
	checkDesc := "Validates total physical memory and usage levels."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get memory information from free command
	memInfoCmd := "free -h"
	memInfoOutput, err := utils.RunCommand("bash", "-c", memInfoCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine physical memory information", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'free' command is available.")
		r.AddCheck(check)
		return
	}

	// Get detailed memory information from /proc/meminfo
	procMemInfoCmd := "cat /proc/meminfo"
	procMemInfoOutput, _ := utils.RunCommand("bash", "-c", procMemInfoCmd)

	// Get memory usage over time
	memUsageCmd := "vmstat 1 3"
	memUsageOutput, _ := utils.RunCommand("bash", "-c", memUsageCmd)

	var detail strings.Builder
	detail.WriteString("Memory Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(memInfoOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nDetailed Memory Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(procMemInfoOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nMemory Usage Over Time:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(memUsageOutput)
	detail.WriteString("\n----\n")

	// Extract total memory in KB from /proc/meminfo
	totalMemory := 0
	for _, line := range strings.Split(procMemInfoOutput, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				totalMemory, _ = strconv.Atoi(parts[1])
				break
			}
		}
	}

	// Extract available memory percentage
	availableMemory := 0
	for _, line := range strings.Split(procMemInfoOutput, "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				availableMemory, _ = strconv.Atoi(parts[1])
				break
			}
		}
	}

	// Calculate memory usage percentage
	memoryUsagePercent := 0
	if totalMemory > 0 && availableMemory > 0 {
		memoryUsagePercent = 100 - (availableMemory * 100 / totalMemory)
	}

	// Convert KB to GB for display
	totalMemoryGB := float64(totalMemory) / 1024 / 1024

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate memory configuration
	if totalMemory == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine total physical memory", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if /proc/meminfo is readable.")
	} else if totalMemoryGB < 2.0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("System has low physical memory: %.2f GB", totalMemoryGB),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider increasing RAM to at least 4 GB for optimal performance.")
		report.AddRecommendation(&check.Result, fmt.Sprintf("For RHEL %s memory recommendations, refer to: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion))
	} else if memoryUsagePercent > 90 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High memory usage: %d%%", memoryUsagePercent),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate processes consuming memory with 'top' or 'ps'.")
		report.AddRecommendation(&check.Result, "Consider adding more RAM if this is a consistent pattern.")
		report.AddRecommendation(&check.Result, fmt.Sprintf("For RHEL %s memory management, refer to: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("System has %.2f GB of physical memory with %d%% usage", totalMemoryGB, memoryUsagePercent),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSwapConfiguration confirms swap is configured, sized correctly, and active
func checkSwapConfiguration(r *report.AsciiDocReport) {
	checkID := "memory-swap"
	checkName := "Swap Configuration"
	checkDesc := "Confirms swap is configured, sized correctly, and active."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get swap information from free command
	swapInfoCmd := "free -h"
	swapInfoOutput, err := utils.RunCommand("bash", "-c", swapInfoCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine swap information", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'free' command is available.")
		r.AddCheck(check)
		return
	}

	// Get detailed swap information
	swapDetailCmd := "swapon --show"
	swapDetailOutput, _ := utils.RunCommand("bash", "-c", swapDetailCmd)

	// Get swap usage over time
	swapUsageCmd := "vmstat 1 3"
	swapUsageOutput, _ := utils.RunCommand("bash", "-c", swapUsageCmd)

	var detail strings.Builder
	detail.WriteString("Swap Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(swapInfoOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nSwap Details:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(swapDetailOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nSwap Usage Over Time:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(swapUsageOutput)
	detail.WriteString("\n----\n")

	// Extract total swap and physical memory in KB from /proc/meminfo
	totalSwap := 0
	totalMemory := 0
	for _, line := range strings.Split(swapInfoOutput, "\n") {
		if strings.HasPrefix(line, "Mem:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Parse human-readable value (approximate)
				memStr := parts[1]
				if strings.HasSuffix(memStr, "G") {
					memVal, _ := strconv.ParseFloat(memStr[:len(memStr)-1], 64)
					totalMemory = int(memVal * 1024 * 1024) // Convert to KB
				} else if strings.HasSuffix(memStr, "M") {
					memVal, _ := strconv.ParseFloat(memStr[:len(memStr)-1], 64)
					totalMemory = int(memVal * 1024) // Convert to KB
				}
			}
		} else if strings.HasPrefix(line, "Swap:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Parse human-readable value (approximate)
				swapStr := parts[1]
				if strings.HasSuffix(swapStr, "G") {
					swapVal, _ := strconv.ParseFloat(swapStr[:len(swapStr)-1], 64)
					totalSwap = int(swapVal * 1024 * 1024) // Convert to KB
				} else if strings.HasSuffix(swapStr, "M") {
					swapVal, _ := strconv.ParseFloat(swapStr[:len(swapStr)-1], 64)
					totalSwap = int(swapVal * 1024) // Convert to KB
				}
			}
		}
	}

	// Get more precise swap and memory values from /proc/meminfo
	procMemInfoCmd := "cat /proc/meminfo | grep -E 'SwapTotal|MemTotal'"
	procMemInfoOutput, _ := utils.RunCommand("bash", "-c", procMemInfoCmd)

	for _, line := range strings.Split(procMemInfoOutput, "\n") {
		if strings.HasPrefix(line, "SwapTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				totalSwap, _ = strconv.Atoi(parts[1])
			}
		} else if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				totalMemory, _ = strconv.Atoi(parts[1])
			}
		}
	}

	// Convert KB to GB for display
	totalSwapGB := float64(totalSwap) / 1024 / 1024
	totalMemoryGB := float64(totalMemory) / 1024 / 1024

	// Red Hat recommends swap size based on RAM amount
	// For systems with <2GB RAM: 2x RAM
	// For systems with 2-8GB RAM: 1x RAM
	// For systems with 8-64GB RAM: 0.5x RAM
	// For systems with >64GB RAM: 4GB minimum
	recommendedSwapGB := 0.0
	if totalMemoryGB < 2.0 {
		recommendedSwapGB = totalMemoryGB * 2
	} else if totalMemoryGB <= 8.0 {
		recommendedSwapGB = totalMemoryGB
	} else if totalMemoryGB <= 64.0 {
		recommendedSwapGB = totalMemoryGB * 0.5
	} else {
		recommendedSwapGB = 4.0
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate swap configuration
	if totalSwap == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"No swap space configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Configure swap space of approximately %.1f GB", recommendedSwapGB))
		report.AddRecommendation(&check.Result, "Use 'swapoff -a' then 'mkswap /dev/device' and 'swapon -a' to configure swap.")
		report.AddRecommendation(&check.Result, fmt.Sprintf("For RHEL %s swap space recommendations, refer to: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/#Storage", rhelVersion))
	} else if totalSwapGB < (recommendedSwapGB * 0.5) {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Swap space (%.2f GB) may be undersized compared to recommended value (%.2f GB)", totalSwapGB, recommendedSwapGB),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Consider increasing swap space to approximately %.1f GB", recommendedSwapGB))
		report.AddRecommendation(&check.Result, fmt.Sprintf("For RHEL %s swap space configuration, refer to: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/#Storage", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Swap space is configured correctly (%.2f GB)", totalSwapGB),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkVMTuningParameters evaluates swappiness and virtual memory tuning parameters
func checkVMTuningParameters(r *report.AsciiDocReport) {
	checkID := "memory-vm-tuning"
	checkName := "VM Tuning Parameters"
	checkDesc := "Evaluates swappiness and virtual memory tuning parameters."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Get current swappiness value
	swappinessCmd := "cat /proc/sys/vm/swappiness"
	swappinessOutput, err := utils.RunCommand("bash", "-c", swappinessCmd)
	swappiness := strings.TrimSpace(swappinessOutput)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine VM swappiness", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if /proc/sys/vm/swappiness is readable.")
		r.AddCheck(check)
		return
	}

	// Get other important VM parameters
	vmParamsCmd := "cat /proc/sys/vm/dirty_ratio /proc/sys/vm/dirty_background_ratio /proc/sys/vm/vfs_cache_pressure"
	vmParamsOutput, _ := utils.RunCommand("bash", "-c", vmParamsCmd)
	vmParams := strings.Split(strings.TrimSpace(vmParamsOutput), "\n")

	dirtyRatio := "N/A"
	dirtyBgRatio := "N/A"
	cachePressure := "N/A"

	if len(vmParams) >= 3 {
		dirtyRatio = vmParams[0]
		dirtyBgRatio = vmParams[1]
		cachePressure = vmParams[2]
	}

	// Check if vm.swappiness is set in sysctl
	sysctlSwapCmd := "sysctl -a | grep vm.swappiness"
	sysctlSwapOutput, _ := utils.RunCommand("bash", "-c", sysctlSwapCmd)

	// Check transparent hugepages status
	thpCmd := "cat /sys/kernel/mm/transparent_hugepage/enabled || echo 'Not available'"
	thpOutput, _ := utils.RunCommand("bash", "-c", thpCmd)
	thpEnabled := strings.TrimSpace(thpOutput)

	var detail strings.Builder
	detail.WriteString("VM Tuning Parameters:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("VM Swappiness: %s\n", swappiness))
	detail.WriteString(fmt.Sprintf("Dirty Ratio: %s\n", dirtyRatio))
	detail.WriteString(fmt.Sprintf("Dirty Background Ratio: %s\n", dirtyBgRatio))
	detail.WriteString(fmt.Sprintf("VFS Cache Pressure: %s\n", cachePressure))
	detail.WriteString(fmt.Sprintf("Transparent Hugepages: %s\n", thpEnabled))
	detail.WriteString("\n----\n")

	detail.WriteString("\nSysctl Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sysctlSwapOutput)
	detail.WriteString("\n----\n")

	// Parse swappiness value
	swappinessVal, err := strconv.Atoi(swappiness)
	if err != nil {
		swappinessVal = -1
	}

	// Parse cache pressure value
	cachePressureVal, err := strconv.Atoi(cachePressure)
	if err != nil {
		cachePressureVal = -1
	}

	// Check if transparent hugepages are enabled
	thpIssue := false
	if strings.Contains(thpEnabled, "[always]") {
		thpIssue = true
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate VM parameters
	issues := []string{}

	// Check swappiness (10-30 is often recommended for servers)
	if swappinessVal > 60 {
		issues = append(issues, fmt.Sprintf("Swappiness value of %d is high for a server environment", swappinessVal))
	}

	// Check cache pressure
	if cachePressureVal > 100 {
		issues = append(issues, fmt.Sprintf("VFS cache pressure of %d is high and may impact file access performance", cachePressureVal))
	}

	// Check transparent hugepages
	if thpIssue {
		issues = append(issues, "Transparent hugepages are set to 'always' which can cause issues with some applications")
	}

	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d VM tuning parameter issues", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if swappinessVal > 60 {
			report.AddRecommendation(&check.Result, "Consider setting vm.swappiness to a lower value (10-30) for server workloads: 'sysctl -w vm.swappiness=10'")
			report.AddRecommendation(&check.Result, "Make the change persistent in /etc/sysctl.conf: 'vm.swappiness=10'")
		}

		if thpIssue {
			report.AddRecommendation(&check.Result, "Consider setting transparent_hugepage to 'madvise' or 'never' for most applications")
		}

		// Add reference link directly instead of as a recommendation
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"VM tuning parameters are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
