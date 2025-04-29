// pkg/checks/satellite/insights.go

package satellite

import (
	"fmt"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"strconv"
	"strings"
)

// RunInsightsChecks performs Satellite Insights integration checks
func RunInsightsChecks(r *report.AsciiDocReport) {
	// Check Red Hat Insights integration
	checkInsightsIntegration(r)
}

// checkInsightsIntegration checks Red Hat Insights integration
func checkInsightsIntegration(r *report.AsciiDocReport) {
	checkID := "satellite-insights"
	checkName := "Red Hat Insights Integration"
	checkDesc := "Checks Satellite's integration with Red Hat Insights."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Red Hat Insights Integration Analysis:\n\n")

	// Check if Insights client is installed
	clientCmd := "rpm -qa insights-client"
	clientOutput, _ := utils.RunCommand("bash", "-c", clientCmd)

	detail.WriteString("Insights Client Installation:\n")
	if clientOutput == "" {
		detail.WriteString("Red Hat Insights client not installed\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(clientOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Insights client configuration
	configCmd := "cat /etc/insights-client/insights-client.conf 2>/dev/null | grep -v '^#'"
	configOutput, _ := utils.RunCommand("bash", "-c", configCmd)

	detail.WriteString("Insights Client Configuration:\n")
	if configOutput == "" {
		detail.WriteString("No Insights client configuration found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(configOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check if client is registered
	regStatusCmd := "insights-client --status 2>/dev/null || echo 'Command not found'"
	regStatusOutput, _ := utils.RunCommand("bash", "-c", regStatusCmd)

	detail.WriteString("Insights Registration Status:\n")
	if strings.Contains(regStatusOutput, "Command not found") {
		detail.WriteString("insights-client command not available\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(regStatusOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Insights in Satellite
	satInsightsCmd := "hammer settings list --search 'name ~ rh_telemetry'"
	satInsightsOutput, _ := utils.RunCommand("bash", "-c", satInsightsCmd)

	detail.WriteString("Satellite Insights Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(satInsightsOutput)
	detail.WriteString("\n----\n\n")

	// Get default organization ID
	defaultOrgID := getDefaultOrganizationID()

	// Improved host analysis with accurate counting of registered hosts
	// Get all hosts listing with content view and lifecycle environment
	hostListCmd := fmt.Sprintf("hammer host list --per-page 1000 --fields 'Name,Content View,Lifecycle Environment'")
	// If we found a default org ID, use it
	if defaultOrgID != "" {
		hostListCmd = fmt.Sprintf("hammer host list --organization-id %s --per-page 1000 --fields 'Name,Content View,Lifecycle Environment'", defaultOrgID)
	}
	hostListOutput, _ := utils.RunCommand("bash", "-c", hostListCmd)

	// Count total hosts by counting lines and removing headers/footers
	hostLines := strings.Split(hostListOutput, "\n")
	totalHosts := 0
	registeredHosts := 0
	var hostNames []string

	// Process host list to count properly registered hosts (with Content View)
	for _, line := range hostLines {
		line = strings.TrimSpace(line)
		// Skip header/footer/empty lines
		if line == "" || strings.Contains(line, "----") || strings.Contains(line, "NAME") {
			continue
		}

		totalHosts++
		fields := strings.Split(line, "|")
		if len(fields) >= 3 {
			hostName := strings.TrimSpace(fields[0])
			contentView := strings.TrimSpace(fields[1])
			hostNames = append(hostNames, hostName)

			// If content view is not empty, count as registered
			if contentView != "" {
				registeredHosts++
			}
		}
	}

	// Check for hosts with Insights enabled and hosts with issues
	insightsEnabledCount := 0
	var sampleInsightsHost string
	var insightsEnabledHosts []string
	var hostsWithIssues []string

	// Track issues by type for reporting
	type HostIssue struct {
		Name   string
		Issues []string
	}
	var hostIssueDetails []HostIssue

	// Check each host for Insights parameter and issues
	for _, hostName := range hostNames {
		// Use a random sample for performance - up to 10 hosts to check
		if len(insightsEnabledHosts) >= 5 && len(hostIssueDetails) >= 5 {
			break
		}

		hostInfoCmd := fmt.Sprintf("hammer host info --name '%s'", hostName)
		hostInfoOutput, _ := utils.RunCommand("bash", "-c", hostInfoCmd)

		// Check if the host has Insights enabled
		if strings.Contains(hostInfoOutput, "host_registration_insights => true") {
			insightsEnabledCount++

			// Keep track of hosts with Insights enabled for reporting
			if len(insightsEnabledHosts) < 5 {
				insightsEnabledHosts = append(insightsEnabledHosts, hostName)

				// Save one sample host for detailed display
				if sampleInsightsHost == "" {
					sampleInsightsHost = hostName
				}
			}
		}

		// Check for critical issues with this host
		var hostIssues []string

		// 1. Check for Global Status Error
		if strings.Contains(hostInfoOutput, "Global Status: Error") {
			hostIssues = append(hostIssues, "Global Status Error")
		}

		// 2. Check for empty content view
		if strings.Contains(hostInfoOutput, "Content view environments:") &&
			!strings.Contains(hostInfoOutput, "Content view environments:") {
			hostIssues = append(hostIssues, "No Content View assigned")
		}

		// 3. Check for subscription issues
		if strings.Contains(hostInfoOutput, "Subscription Information:") &&
			strings.Contains(hostInfoOutput, "Uuid:            \n") {
			hostIssues = append(hostIssues, "No subscription")
		}

		// 4. Check if Insights is disabled despite being registered
		if !strings.Contains(hostInfoOutput, "host_registration_insights => true") {
			hostIssues = append(hostIssues, "Insights disabled")
		}

		// 5. Check if Remote Execution is disabled
		if !strings.Contains(hostInfoOutput, "host_registration_remote_execution => true") {
			hostIssues = append(hostIssues, "Remote Execution disabled")
		}

		// If this host has issues, add it to our list
		if len(hostIssues) > 0 {
			hostsWithIssues = append(hostsWithIssues, hostName)

			// Keep details for up to 5 hosts with issues
			if len(hostIssueDetails) < 5 {
				hostIssueDetails = append(hostIssueDetails, HostIssue{
					Name:   hostName,
					Issues: hostIssues,
				})
			}
		}
	}
	detail.WriteString("Host Registration Summary:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Total hosts: %d\n", totalHosts))
	detail.WriteString(fmt.Sprintf("Hosts with Content View (properly registered): %d\n", registeredHosts))
	detail.WriteString(fmt.Sprintf("Hosts with Insights enabled (sampled): %d\n", insightsEnabledCount))
	detail.WriteString("\n----\n\n")

	// If we have hosts with issues, show that information first
	if len(hostIssueDetails) > 0 {
		detail.WriteString("Hosts with Issues:\n")
		detail.WriteString("{set:cellbgcolor!}\n")
		detail.WriteString("|===\n")
		detail.WriteString("|Host Name|Issues\n\n")

		for _, hostIssue := range hostIssueDetails {
			detail.WriteString(fmt.Sprintf("|%s|%s\n",
				hostIssue.Name,
				strings.Join(hostIssue.Issues, ", ")))
		}

		if len(hostsWithIssues) > len(hostIssueDetails) {
			detail.WriteString(fmt.Sprintf("|Note|%d additional hosts with issues not shown\n",
				len(hostsWithIssues)-len(hostIssueDetails)))
		}

		detail.WriteString("|===\n\n")
	}

	// Show a sample of hosts with content views (just first few rows)
	detail.WriteString("Host List with Content Views (Sample):\n")
	detail.WriteString("[source, bash]\n----\n")

	// Only show header and first 5 data rows
	hostListLines := strings.Split(hostListOutput, "\n")
	headerShown := false
	dataRows := 0

	for _, line := range hostListLines {
		if strings.Contains(line, "NAME") || strings.Contains(line, "----") {
			detail.WriteString(line + "\n")
			headerShown = true
		} else if headerShown && line != "" && dataRows < 5 {
			detail.WriteString(line + "\n")
			dataRows++
		}
	}

	if totalHosts > 5 {
		detail.WriteString(fmt.Sprintf("... and %d more hosts\n", totalHosts-5))
	}

	detail.WriteString("\n----\n\n")

	// If we have a sample host with Insights, show focused information
	if sampleInsightsHost != "" {
		sampleHostInfoCmd := fmt.Sprintf("hammer host info --name '%s'", sampleInsightsHost)
		sampleHostInfoOutput, _ := utils.RunCommand("bash", "-c", sampleHostInfoCmd)

		detail.WriteString(fmt.Sprintf("Sample Host with Insights (%s) - Key Information:\n", sampleInsightsHost))
		detail.WriteString("[source, bash]\n----\n")

		// Extract and display only the most important fields
		hostInfoLines := strings.Split(sampleHostInfoOutput, "\n")
		currentSection := ""

		for _, line := range hostInfoLines {
			// Track which section we're in
			if strings.HasSuffix(line, ":") && !strings.Contains(line, "|") {
				currentSection = strings.TrimSuffix(line, ":")
			}

			// Only show the most important fields
			if strings.Contains(line, "Name:") ||
				strings.Contains(line, "Organization:") ||
				strings.Contains(line, "Status:") ||
				line == "    Global Status: Error" ||
				strings.Contains(line, "Operating System:") ||
				line == "Parameters:" ||
				strings.Contains(line, "host_registration_insights") ||
				strings.Contains(line, "host_registration_remote_execution") ||
				currentSection == "Content Information" ||
				currentSection == "Subscription Information" {
				detail.WriteString(line + "\n")
			}
		}
		detail.WriteString("\n----\n")
	}

	// Determine Insights status
	hasClient := clientOutput != ""
	isRegistered := regStatusOutput != "" && !strings.Contains(regStatusOutput, "Command not found") &&
		!strings.Contains(regStatusOutput, "unregistered")
	insightsEnabled := strings.Contains(satInsightsOutput, "true") &&
		!strings.Contains(satInsightsOutput, "rh_telemetry_enabled | false")
	hasInsightsHosts := insightsEnabledCount > 0

	// Evaluate results
	if !hasClient {
		check.Result = report.NewResult(report.StatusWarning,
			"Red Hat Insights client not installed",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider installing insights-client for proactive monitoring")
		report.AddRecommendation(&check.Result, "Run: yum install insights-client")
	} else if !isRegistered {
		check.Result = report.NewResult(report.StatusWarning,
			"Insights client installed but not registered",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Register with Insights: insights-client --register")
	} else if !insightsEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Insights client registered but not enabled in Satellite",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable Insights integration in Satellite settings")
	} else if !hasInsightsHosts {
		check.Result = report.NewResult(report.StatusWarning,
			"Insights enabled but no hosts reporting to Insights",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Configure hosts to report to Insights")
		report.AddRecommendation(&check.Result, "Verify Insights client is installed on managed hosts")
		report.AddRecommendation(&check.Result, "Set host_registration_insights => true in host parameters")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Red Hat Insights integration is properly configured",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/host_management_using_the_red_hat_satellite_web_ui",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/products/red-hat-insights")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// RunHostManagementChecks performs checks on Satellite host management
func RunHostManagementChecks(r *report.AsciiDocReport) {
	// Check host counts and distribution
	checkHostCounts(r)

	// Check host registration status
	checkHostRegistration(r)

	// Export host management reports
	exportHostReports(r)
}

// checkHostCounts checks host counts by organization and location
func checkHostCounts(r *report.AsciiDocReport) {
	checkID := "satellite-host-counts"
	checkName := "Host Counts"
	checkDesc := "Analyzes host counts by organization and location."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Host Count Analysis:\n\n")

	// Get default organization ID
	defaultOrgID := getDefaultOrganizationID()

	// Get host list with better field selection
	hostListCmd := "hammer host list --per-page 1000 --fields 'Name,Organization,Location'"
	// If a default organization was found, use it
	if defaultOrgID != "" {
		hostListCmd = fmt.Sprintf("hammer host list --organization-id %s --per-page 1000 --fields 'Name,Organization,Location'", defaultOrgID)
	}
	hostListOutput, _ := utils.RunCommand("bash", "-c", hostListCmd)

	// Parse host list to count totals
	hostLines := strings.Split(hostListOutput, "\n")
	totalHosts := 0
	hostsByOrg := make(map[string]int)
	hostsByLoc := make(map[string]int)

	for _, line := range hostLines {
		line = strings.TrimSpace(line)
		// Skip header/footer/empty lines
		if line == "" || strings.Contains(line, "----") || strings.Contains(line, "NAME") {
			continue
		}

		totalHosts++
		fields := strings.Split(line, "|")
		if len(fields) >= 3 {
			org := strings.TrimSpace(fields[1])
			loc := strings.TrimSpace(fields[2])

			if org != "" {
				hostsByOrg[org]++
			}

			if loc != "" {
				hostsByLoc[loc]++
			}
		}
	}

	detail.WriteString("Total Hosts:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Total host count: %d\n\n", totalHosts))
	detail.WriteString("Sample of registered hosts:\n")

	// Show only a portion of the host list if it's long
	if totalHosts > 5 {
		sampleCount := 0
		for _, line := range hostLines {
			if sampleCount >= 5 {
				break
			}
			if !strings.Contains(line, "----") && !strings.Contains(line, "NAME") && line != "" {
				detail.WriteString(line + "\n")
				sampleCount++
			} else if strings.Contains(line, "NAME") || strings.Contains(line, "----") {
				detail.WriteString(line + "\n")
			}
		}
	} else {
		detail.WriteString(hostListOutput)
	}
	detail.WriteString("\n----\n\n")

	// Get hosts by organization from our counted data
	detail.WriteString("Host Counts by Organization:\n")
	detail.WriteString("[source, bash]\n----\n")
	if len(hostsByOrg) > 0 {
		for org, count := range hostsByOrg {
			detail.WriteString(fmt.Sprintf("Organization: %s\n", org))
			detail.WriteString(fmt.Sprintf("Host count: %d\n\n", count))
		}
	} else {
		detail.WriteString("No organizations found\n\n")
	}
	detail.WriteString("\n----\n\n")

	// Get hosts by location from our counted data
	detail.WriteString("Host Counts by Location:\n")
	detail.WriteString("[source, bash]\n----\n")
	if len(hostsByLoc) > 0 {
		for loc, count := range hostsByLoc {
			detail.WriteString(fmt.Sprintf("Location: %s\n", loc))
			detail.WriteString(fmt.Sprintf("Host count: %d\n\n", count))
		}
	} else {
		detail.WriteString("No locations found\n")
	}
	detail.WriteString("\n----\n")

	// Evaluate results
	if totalHosts == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"No hosts registered in Satellite",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Register hosts to utilize Satellite functionality")
	} else if totalHosts < 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Only %d hosts registered in Satellite", totalHosts),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider registering more hosts to maximize Satellite value")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d hosts registered in Satellite", totalHosts),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkHostRegistration checks host registration status
func checkHostRegistration(r *report.AsciiDocReport) {
	checkID := "satellite-host-registration"
	checkName := "Host Registration Status"
	checkDesc := "Checks status of host registrations with Satellite."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Host Registration Status Analysis:\n\n")

	// Get default organization ID
	defaultOrgID := getDefaultOrganizationID()

	// Get content view information for all hosts
	hostCVCmd := "hammer host list --per-page 1000 --fields 'Name,Content View,Lifecycle Environment'"
	// If a default organization was found, use it
	if defaultOrgID != "" {
		hostCVCmd = fmt.Sprintf("hammer host list --organization-id %s --per-page 1000 --fields 'Name,Content View,Lifecycle Environment'", defaultOrgID)
	}
	hostCVOutput, _ := utils.RunCommand("bash", "-c", hostCVCmd)

	// Parse the host list to analyze registration status
	hostLines := strings.Split(hostCVOutput, "\n")
	totalHosts := 0
	registeredHosts := 0
	unregisteredHosts := 0
	var unregisteredHostNames []string

	// For detailed issue tracking
	type HostWithIssues struct {
		Name               string
		Issues             []string
		GlobalStatus       string
		ContentView        string
		LifecycleEnv       string
		InsightsEnabled    bool
		RemoteExecEnabled  bool
		SubscriptionStatus string
		OperatingSystem    string
	}
	var problemHosts []HostWithIssues

	for _, line := range hostLines {
		line = strings.TrimSpace(line)
		// Skip header/footer/empty lines
		if line == "" || strings.Contains(line, "----") || strings.Contains(line, "NAME") {
			continue
		}

		totalHosts++
		fields := strings.Split(line, "|")
		if len(fields) >= 3 {
			hostName := strings.TrimSpace(fields[0])
			contentView := strings.TrimSpace(fields[1])
			lifecycleEnv := ""
			if len(fields) >= 4 {
				lifecycleEnv = strings.TrimSpace(fields[2])
			}

			// If content view is empty, host is not properly registered
			if contentView == "" {
				unregisteredHosts++
				if len(unregisteredHostNames) < 5 { // Keep a sample of unregistered hosts
					unregisteredHostNames = append(unregisteredHostNames, hostName)
				}

				// For deeper analysis - limit to 5 hosts
				if len(problemHosts) < 10 {
					// Get detailed info for this problematic host
					hostInfoCmd := fmt.Sprintf("hammer host info --name '%s'", hostName)
					hostInfoOutput, _ := utils.RunCommand("bash", "-c", hostInfoCmd)

					// Extract key information
					globalStatus := "Unknown"
					insightsEnabled := false
					remoteExecEnabled := false
					subscriptionStatus := "Unknown"
					operatingSystem := "Unknown"

					// Parse host info output
					hostInfoLines := strings.Split(hostInfoOutput, "\n")
					for i, line := range hostInfoLines {
						if strings.Contains(line, "Global Status:") {
							globalStatus = strings.TrimSpace(strings.TrimPrefix(line, "Global Status:"))
						} else if strings.Contains(line, "host_registration_insights => true") {
							insightsEnabled = true
						} else if strings.Contains(line, "host_registration_remote_execution => true") {
							remoteExecEnabled = true
						} else if strings.Contains(line, "Operating System:") && i+1 < len(hostInfoLines) {
							operatingSystem = strings.TrimSpace(hostInfoLines[i+1])
						}
					}

					// Compile issues list
					var issues []string
					if contentView == "" {
						issues = append(issues, "No Content View")
					}
					if lifecycleEnv == "" {
						issues = append(issues, "No Lifecycle Environment")
					}
					if globalStatus == "Error" {
						issues = append(issues, "Global Status Error")
					}
					if !insightsEnabled {
						issues = append(issues, "Insights Disabled")
					}
					if !remoteExecEnabled {
						issues = append(issues, "Remote Execution Disabled")
					}

					// Add to problem hosts list
					problemHosts = append(problemHosts, HostWithIssues{
						Name:               hostName,
						Issues:             issues,
						GlobalStatus:       globalStatus,
						ContentView:        contentView,
						LifecycleEnv:       lifecycleEnv,
						InsightsEnabled:    insightsEnabled,
						RemoteExecEnabled:  remoteExecEnabled,
						SubscriptionStatus: subscriptionStatus,
						OperatingSystem:    operatingSystem,
					})
				}
			} else {
				registeredHosts++

				// Even registered hosts might have issues - sample a few to check
				if len(problemHosts) < 10 && totalHosts%10 == 0 { // Sample ~10% of hosts, up to 10 total
					hostInfoCmd := fmt.Sprintf("hammer host info --name '%s'", hostName)
					hostInfoOutput, _ := utils.RunCommand("bash", "-c", hostInfoCmd)

					// Check for issues in registered hosts
					globalStatus := "Unknown"
					insightsEnabled := false
					remoteExecEnabled := false
					subscriptionStatus := "Unknown"
					operatingSystem := "Unknown"

					// Parse host info output
					hostInfoLines := strings.Split(hostInfoOutput, "\n")
					for i, line := range hostInfoLines {
						if strings.Contains(line, "Global Status:") {
							globalStatus = strings.TrimSpace(strings.TrimPrefix(line, "Global Status:"))
						} else if strings.Contains(line, "host_registration_insights => true") {
							insightsEnabled = true
						} else if strings.Contains(line, "host_registration_remote_execution => true") {
							remoteExecEnabled = true
						} else if strings.Contains(line, "Operating System:") && i+1 < len(hostInfoLines) {
							operatingSystem = strings.TrimSpace(hostInfoLines[i+1])
						}
					}

					// Check for issues
					var issues []string
					if globalStatus == "Error" {
						issues = append(issues, "Global Status Error")
					}
					if !insightsEnabled {
						issues = append(issues, "Insights Disabled")
					}
					if !remoteExecEnabled {
						issues = append(issues, "Remote Execution Disabled")
					}

					// Only add if issues were found
					if len(issues) > 0 {
						problemHosts = append(problemHosts, HostWithIssues{
							Name:               hostName,
							Issues:             issues,
							GlobalStatus:       globalStatus,
							ContentView:        contentView,
							LifecycleEnv:       lifecycleEnv,
							InsightsEnabled:    insightsEnabled,
							RemoteExecEnabled:  remoteExecEnabled,
							SubscriptionStatus: subscriptionStatus,
							OperatingSystem:    operatingSystem,
						})
					}
				}
			}
		}
	}

	// Get a small sample of hosts to check for subscription issues
	// We'll examine up to 5 hosts for performance reasons
	var hostsWithSubIssues []string
	var hostsNotCheckingIn []string

	// From the host list, sample a few hosts to check their status
	sampleCount := 0
	for _, line := range hostLines {
		if sampleCount >= 5 {
			break
		}

		line = strings.TrimSpace(line)
		// Skip header/footer/empty lines
		if line == "" || strings.Contains(line, "----") || strings.Contains(line, "NAME") {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) >= 1 {
			hostName := strings.TrimSpace(fields[0])

			// Get detailed host info to check status
			hostInfoCmd := fmt.Sprintf("hammer host info --name '%s'", hostName)
			hostInfoOutput, _ := utils.RunCommand("bash", "-c", hostInfoCmd)

			// Check for subscription issues
			if strings.Contains(hostInfoOutput, "Global Status: Error") {
				hostsWithSubIssues = append(hostsWithSubIssues, hostName)
			}

			// Check last checkin time
			if strings.Contains(hostInfoOutput, "Last Checkin:") && !strings.Contains(hostInfoOutput, "Last Checkin:    ") {
				// Parse the last checkin date and compare it to now
				// For simplicity, we'll just check if it contains a date
				// A more sophisticated implementation would parse and compare dates
			} else {
				hostsNotCheckingIn = append(hostsNotCheckingIn, hostName)
			}

			sampleCount++
		}
	}

	// Attempt to identify hosts with Katello agent installed
	// This is difficult to do reliably, so we'll use a best effort approach
	katelloAgentCount := 0
	katelloAgentDetectionCmd := "hammer host list --per-page 10 | grep -v '^--\\|^ID' | awk '{print $2}' | head -5 | xargs -I {} hammer host info --name {} | grep -c 'katello-agent'"
	katelloAgentOutput, _ := utils.RunCommand("bash", "-c", katelloAgentDetectionCmd)
	if katelloCount, err := strconv.Atoi(strings.TrimSpace(katelloAgentOutput)); err == nil {
		katelloAgentCount = katelloCount
	}

	// Count hosts with remote execution capability
	remoteExecCount := 0
	remoteExecDetectionCmd := "hammer host list --per-page 10 | grep -v '^--\\|^ID' | awk '{print $2}' | head -5 | xargs -I {} hammer host info --name {} | grep -c 'host_registration_remote_execution => true'"
	remoteExecOutput, _ := utils.RunCommand("bash", "-c", remoteExecDetectionCmd)
	if remoteExecCountVal, err := strconv.Atoi(strings.TrimSpace(remoteExecOutput)); err == nil {
		remoteExecCount = remoteExecCountVal
	}

	detail.WriteString("Host Registration Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Total hosts: %d\n", totalHosts))
	detail.WriteString(fmt.Sprintf("Properly registered hosts (with Content View): %d\n", registeredHosts))
	detail.WriteString(fmt.Sprintf("Unregistered hosts: %d\n", unregisteredHosts))

	if len(hostsWithSubIssues) > 0 {
		detail.WriteString(fmt.Sprintf("\nHosts with subscription issues (sampled): %d\n", len(hostsWithSubIssues)))
		for _, host := range hostsWithSubIssues {
			detail.WriteString(fmt.Sprintf("- %s\n", host))
		}
	}

	if len(hostsNotCheckingIn) > 0 {
		detail.WriteString(fmt.Sprintf("\nHosts not checking in (sampled): %d\n", len(hostsNotCheckingIn)))
		for _, host := range hostsNotCheckingIn {
			detail.WriteString(fmt.Sprintf("- %s\n", host))
		}
	}

	if len(unregisteredHostNames) > 0 {
		detail.WriteString(fmt.Sprintf("\nSample of unregistered hosts:\n"))
		for _, host := range unregisteredHostNames {
			detail.WriteString(fmt.Sprintf("- %s\n", host))
		}
	}

	if katelloAgentCount > 0 {
		detail.WriteString(fmt.Sprintf("\nHosts with Katello Agent (DEPRECATED): %d (sampled)\n", katelloAgentCount))
	}

	if remoteExecCount > 0 {
		detail.WriteString(fmt.Sprintf("\nHosts with Remote Execution: %d (sampled)\n", remoteExecCount))
	}
	detail.WriteString("\n----\n\n")

	// Show content view status
	detail.WriteString("Host Content View Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hostCVOutput)
	detail.WriteString("\n----\n\n")

	// Evaluate results
	subIssueCount := len(hostsWithSubIssues)
	notCheckingInCount := len(hostsNotCheckingIn)

	if unregisteredHosts > 10 || subIssueCount > 10 || notCheckingInCount > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Host registration issues detected: %d unregistered, %d subscription issues, %d not checking in",
				unregisteredHosts, subIssueCount, notCheckingInCount),
			report.ResultKeyRecommended)

		if unregisteredHosts > 0 {
			report.AddRecommendation(&check.Result, "Register unregistered hosts with Satellite")
		}
		if subIssueCount > 0 {
			report.AddRecommendation(&check.Result, "Resolve subscription issues with affected hosts")
		}
		if notCheckingInCount > 0 {
			report.AddRecommendation(&check.Result, "Investigate hosts not checking in for connectivity issues")
		}
	} else if katelloAgentCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d hosts using deprecated Katello agent (will be removed in Satellite 6.15)", katelloAgentCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Migrate from Katello agent to Remote Execution or Remote Execution Pull Mode")
		report.AddRecommendation(&check.Result, "Without migration, critical host package actions including patching and security updates will fail in Satellite 6.15")
	} else if unregisteredHosts > 0 || subIssueCount > 0 || notCheckingInCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Minor host registration issues detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review host registration status for minor issues")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Host registration status appears good",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/registering_hosts",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// exportHostReports exports various host management reports
func exportHostReports(r *report.AsciiDocReport) {
	checkID := "satellite-host-reports"
	checkName := "Host Management Reports"
	checkDesc := "Exports various host management reports and statistics."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Host Management Reports:\n\n")

	// Get default organization ID
	defaultOrgID := getDefaultOrganizationID()

	// Get list of organizations
	orgListCmd := "hammer organization list --fields id,name"
	orgListOutput, _ := utils.RunCommand("bash", "-c", orgListCmd)

	// Get list of locations
	locListCmd := "hammer location list --fields id,name"
	locListOutput, _ := utils.RunCommand("bash", "-c", locListCmd)

	// Parse organizations and locations
	orgLines := strings.Split(orgListOutput, "\n")
	locLines := strings.Split(locListOutput, "\n")

	var orgs []struct {
		ID   string
		Name string
	}

	var locs []struct {
		ID   string
		Name string
	}

	for _, line := range orgLines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Split(line, "|")
			if len(fields) >= 3 {
				orgs = append(orgs, struct {
					ID   string
					Name string
				}{
					ID:   strings.TrimSpace(fields[1]),
					Name: strings.TrimSpace(fields[2]),
				})
			}
		}
	}

	for _, line := range locLines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Split(line, "|")
			if len(fields) >= 3 {
				locs = append(locs, struct {
					ID   string
					Name string
				}{
					ID:   strings.TrimSpace(fields[1]),
					Name: strings.TrimSpace(fields[2]),
				})
			}
		}
	}

	// Build distribution of hosts by org/location
	detail.WriteString("Host Count by Organization and Location:\n")
	detail.WriteString("[source, bash]\n----\n")

	for _, org := range orgs {
		detail.WriteString(fmt.Sprintf("Organization: %s\n", org.Name))

		// Get host count in this org
		orgHostsCountCmd := fmt.Sprintf("hammer host list --organization-id %s --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", org.ID)
		orgHostsCountOutput, _ := utils.RunCommand("bash", "-c", orgHostsCountCmd)
		orgHostCount := 0
		if count, err := strconv.Atoi(strings.TrimSpace(orgHostsCountOutput)); err == nil {
			orgHostCount = count
		}

		detail.WriteString(fmt.Sprintf("Total hosts: %d\n", orgHostCount))

		for _, loc := range locs {
			// Get host count for this org/location combination
			orgLocHostsCountCmd := fmt.Sprintf("hammer host list --organization-id %s --location-id %s --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", org.ID, loc.ID)
			orgLocHostsCountOutput, _ := utils.RunCommand("bash", "-c", orgLocHostsCountCmd)
			orgLocHostCount := 0
			if count, err := strconv.Atoi(strings.TrimSpace(orgLocHostsCountOutput)); err == nil {
				orgLocHostCount = count
			}

			if orgLocHostCount > 0 {
				detail.WriteString(fmt.Sprintf("  Location: %s - %d hosts\n", loc.Name, orgLocHostCount))
			}
		}
		detail.WriteString("\n")
	}
	detail.WriteString("\n----\n\n")

	// Get content view usage (simplified to avoid complex command crafting)
	cvListCmd := "hammer content-view list --fields id,name,composite"
	if defaultOrgID != "" {
		cvListCmd = fmt.Sprintf("hammer content-view list --organization-id %s --fields id,name,composite", defaultOrgID)
	}
	cvListOutput, _ := utils.RunCommand("bash", "-c", cvListCmd)

	detail.WriteString("Content View Usage by Hosts:\n")
	detail.WriteString("[source, bash]\n----\n")

	cvLines := strings.Split(cvListOutput, "\n")
	for _, line := range cvLines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Split(line, "|")
			if len(fields) >= 4 {
				cvName := strings.TrimSpace(fields[2])
				cvType := strings.TrimSpace(fields[3])

				// Get host count using this content view
				cvHostsCountCmd := fmt.Sprintf("hammer host list --search \"content_view = \\\"%s\\\"\" --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", cvName)
				if defaultOrgID != "" {
					cvHostsCountCmd = fmt.Sprintf("hammer host list --organization-id %s --search \"content_view = \\\"%s\\\"\" --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", defaultOrgID, cvName)
				}
				cvHostsCountOutput, _ := utils.RunCommand("bash", "-c", cvHostsCountCmd)
				cvHostCount := 0
				if count, err := strconv.Atoi(strings.TrimSpace(cvHostsCountOutput)); err == nil {
					cvHostCount = count
				}

				if cvType == "Yes" {
					cvType = "Composite"
				} else {
					cvType = "Regular"
				}

				detail.WriteString(fmt.Sprintf("Content View: %s (%s) - %d hosts\n", cvName, cvType, cvHostCount))
			}
		}
	}
	detail.WriteString("\n----\n\n")

	// Get lifecycle environment usage
	leListCmd := "hammer lifecycle-environment list --fields id,name"
	if defaultOrgID != "" {
		leListCmd = fmt.Sprintf("hammer lifecycle-environment list --organization-id %s --fields id,name", defaultOrgID)
	}
	leListOutput, _ := utils.RunCommand("bash", "-c", leListCmd)

	detail.WriteString("Lifecycle Environment Usage by Hosts:\n")
	detail.WriteString("[source, bash]\n----\n")

	leLines := strings.Split(leListOutput, "\n")
	for _, line := range leLines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Split(line, "|")
			if len(fields) >= 3 {
				leName := strings.TrimSpace(fields[2])

				// Get host count using this lifecycle environment
				leHostsCountCmd := fmt.Sprintf("hammer host list --search \"lifecycle_environment = \\\"%s\\\"\" --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", leName)
				if defaultOrgID != "" {
					leHostsCountCmd = fmt.Sprintf("hammer host list --organization-id %s --search \"lifecycle_environment = \\\"%s\\\"\" --per-page 1000 | grep -v '^--\\|^ID\\|Total' | wc -l", defaultOrgID, leName)
				}
				leHostsCountOutput, _ := utils.RunCommand("bash", "-c", leHostsCountCmd)
				leHostCount := 0
				if count, err := strconv.Atoi(strings.TrimSpace(leHostsCountOutput)); err == nil {
					leHostCount = count
				}

				detail.WriteString(fmt.Sprintf("Lifecycle Environment: %s - %d hosts\n", leName, leHostCount))
			}
		}
	}
	detail.WriteString("\n----\n\n")

	// Get Satellite settings (limit output for readability)
	settingsCmd := "hammer settings list | head -30"
	settingsOutput, _ := utils.RunCommand("bash", "-c", settingsCmd)

	detail.WriteString("Satellite Settings (Sample):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(settingsOutput)
	detail.WriteString("\n... (output truncated for brevity) ...\n")
	detail.WriteString("\n----\n")

	// We're just exporting data, so always return OK status
	check.Result = report.NewResult(report.StatusOK,
		"Host management reports exported successfully",
		report.ResultKeyNoChange)

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// RunSyncPlanChecks performs checks on Satellite sync plans
func RunSyncPlanChecks(r *report.AsciiDocReport) {
	// List and analyze sync plans
	checkSyncPlanDetails(r)
}

// checkSyncPlanDetails analyzes sync plans in detail
func checkSyncPlanDetails(r *report.AsciiDocReport) {
	checkID := "satellite-sync-plan-details"
	checkName := "Sync Plan Details"
	checkDesc := "Provides detailed analysis of sync plans and their schedule."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	var detail strings.Builder
	detail.WriteString("Sync Plan Detailed Analysis:\n\n")

	// Get default organization ID
	defaultOrgID := getDefaultOrganizationID()

	// Get list of all sync plans - using organization flag function for proper formatting
	syncPlansCmd := "hammer sync-plan list"
	if defaultOrgID != "" {
		syncPlansCmd += safeOrganizationFlag(defaultOrgID)
	}
	syncPlansOutput, err := utils.RunCommand("bash", "-c", syncPlansCmd)

	if err != nil {
		detail.WriteString("Error retrieving sync plans:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve sync plan information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, fmt.Sprintf("Try specifying organization ID: hammer sync-plan list --organization-id <ID>"))

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_syncing",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("All Sync Plans:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(syncPlansOutput)
	detail.WriteString("\n----\n\n")

	// Get details for each sync plan
	detail.WriteString("Sync Plan Details:\n\n")

	// First, get just the names of sync plans using the fields parameter
	// This avoids confusion with columns and parsing issues
	syncPlanNamesCmd := "hammer sync-plan list --fields=name"
	if defaultOrgID != "" {
		syncPlanNamesCmd += safeOrganizationFlag(defaultOrgID)
	}
	syncPlanNamesOutput, err := utils.RunCommand("bash", "-c", syncPlanNamesCmd)

	if err != nil {
		detail.WriteString("Error retrieving sync plan names:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")
	} else {
		// Process the sync plan names
		var syncPlanNames []string
		lines := strings.Split(syncPlanNamesOutput, "\n")
		for _, line := range lines {
			// Skip header, separator, and empty lines
			line = strings.TrimSpace(line)
			if line == "" || line == "NAME" || strings.Contains(line, "----") {
				continue
			}
			syncPlanNames = append(syncPlanNames, line)
		}

		// Get detailed information for each sync plan by name
		planCount := len(syncPlanNames)
		dailyCount := 0
		weeklyCount := 0
		monthlyCount := 0
		customCount := 0

		for _, name := range syncPlanNames {
			// Get detailed information for this sync plan using name
			planDetailCmd := fmt.Sprintf("hammer sync-plan info --name \"%s\"", name)
			if defaultOrgID != "" {
				planDetailCmd += safeOrganizationFlag(defaultOrgID)
			}
			planDetailOutput, err := utils.RunCommand("bash", "-c", planDetailCmd)

			detail.WriteString(fmt.Sprintf("Sync Plan: %s\n", name))
			detail.WriteString("[source, bash]\n----\n")

			// Handle error for each plan but keep going
			if err != nil {
				detail.WriteString(fmt.Sprintf("Error retrieving sync plan details: %s\n", err.Error()))
			} else {
				detail.WriteString(planDetailOutput)

				// Count by interval type
				if strings.Contains(planDetailOutput, "Interval:          daily") {
					dailyCount++
				} else if strings.Contains(planDetailOutput, "Interval:          weekly") {
					weeklyCount++
				} else if strings.Contains(planDetailOutput, "Interval:          monthly") {
					monthlyCount++
				} else if strings.Contains(planDetailOutput, "Interval:          custom") {
					customCount++
				}
			}

			detail.WriteString("\n----\n")
		}

		// Get products with enabled repositories only
		// Modified to only show products with repositories > 0
		productsWithReposCmd := fmt.Sprintf("hammer --no-headers --csv product list --fields Id,Name,Repositories")
		if defaultOrgID != "" {
			productsWithReposCmd += safeOrganizationFlag(defaultOrgID)
		}
		productsWithReposCmd += " | awk -F, '$3>0{print}'"
		productsWithReposOutput, _ := utils.RunCommand("bash", "-c", productsWithReposCmd)

		// Parse products to count those with enabled repositories but without sync plans
		productsWithoutPlans := 0
		totalProductsWithRepos := 0
		var productsWithoutPlansList []string

		// Process each product with repositories to check if it has a sync plan
		productLines := strings.Split(productsWithReposOutput, "\n")
		for _, line := range productLines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			totalProductsWithRepos++

			// Split CSV line
			fields := strings.Split(line, ",")
			if len(fields) >= 2 {
				productID := strings.TrimSpace(fields[0])
				productName := strings.TrimSpace(fields[1])

				// Check if this product has a sync plan attached
				productInfoCmd := fmt.Sprintf("hammer product info --id %s", productID)
				if defaultOrgID != "" {
					productInfoCmd += safeOrganizationFlag(defaultOrgID)
				}
				productInfoCmd += " --fields \"Sync plan id\""
				productInfoOutput, _ := utils.RunCommand("bash", "-c", productInfoCmd)

				// If the sync plan ID is empty, this product doesn't have a sync plan
				if !strings.Contains(productInfoOutput, "Sync Plan ID:") ||
					strings.Contains(productInfoOutput, "Sync Plan ID:      ") ||
					strings.Contains(productInfoOutput, "Sync Plan ID:\n") {
					productsWithoutPlans++
					if len(productsWithoutPlansList) < 5 && productName != "" {
						productsWithoutPlansList = append(productsWithoutPlansList, productName)
					}
				}
			}
		}

		detail.WriteString("Products With Enabled Repositories Without Sync Plans:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(fmt.Sprintf("Total products with enabled repositories: %d\n", totalProductsWithRepos))
		detail.WriteString(fmt.Sprintf("Products with enabled repositories without sync plans: %d\n\n", productsWithoutPlans))

		if len(productsWithoutPlansList) > 0 {
			detail.WriteString("Sample of products with enabled repositories but no sync plans:\n")
			for _, prod := range productsWithoutPlansList {
				detail.WriteString(fmt.Sprintf("- %s\n", prod))
			}
		}

		detail.WriteString("\n----\n\n")

		// Summary of sync plans
		summaryStr := fmt.Sprintf("Found %d sync plans: %d daily, %d weekly, %d monthly, %d custom",
			planCount, dailyCount, weeklyCount, monthlyCount, customCount)

		// Evaluate results
		if planCount == 0 && totalProductsWithRepos > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				"No sync plans configured, but products with enabled repositories exist",
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Create sync plans to keep content updated")
			report.AddRecommendation(&check.Result, "Configure daily or weekly sync plans for important repositories")
		} else if productsWithoutPlans > 0 && productsWithoutPlans == totalProductsWithRepos && totalProductsWithRepos > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("%s, but no products with enabled repositories are assigned to sync plans", summaryStr),
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Assign sync plans to products with enabled repositories")
		} else if productsWithoutPlans > 0 && totalProductsWithRepos > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("%s, but %d out of %d products with enabled repositories have no sync plans",
					summaryStr, productsWithoutPlans, totalProductsWithRepos),
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Assign sync plans to products with enabled repositories that don't have sync plans")
		} else if planCount > 0 && totalProductsWithRepos == 0 {
			check.Result = report.NewResult(report.StatusInfo,
				fmt.Sprintf("%s, but no products with enabled repositories found", summaryStr),
				report.ResultKeyAdvisory)
			report.AddRecommendation(&check.Result, "Enable repositories for products or consider removing unused sync plans")
		} else {
			check.Result = report.NewResult(report.StatusOK,
				summaryStr,
				report.ResultKeyNoChange)
		}
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_syncing",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
