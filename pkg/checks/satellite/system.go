// pkg/checks/satellite/system.go

package satellite

import (
	"fmt"
	"sort"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// SatelliteVersionInfo stores Satellite version information
type SatelliteVersionInfo struct {
	FullVersion  string // e.g., "6.16.0"
	MajorVersion string // e.g., "6"
	MinorVersion string // e.g., "16"
}

// Global variable to store Satellite version info
var satelliteVersionInfo SatelliteVersionInfo

// GetSatelliteVersion returns the Satellite version information
func GetSatelliteVersion() SatelliteVersionInfo {
	return satelliteVersionInfo
}

// checkSatelliteVersion checks the Satellite version
func checkSatelliteVersion(r *report.AsciiDocReport) {
	checkID := "satellite-version"
	checkName := "Satellite Version"
	checkDesc := "Confirms the Satellite server is running a supported version."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check if satellite-installer exists
	_, err := utils.RunCommand("which", "satellite-installer")
	if err != nil {
		check.Result = report.NewResult(report.StatusCritical,
			"satellite-installer not found. This doesn't appear to be a Satellite server.",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Verify this system is a Red Hat Satellite server.")
		report.AddRecommendation(&check.Result, "If this is intended to be a Satellite server, install Satellite using satellite-installer.")
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_satellite/")
		r.AddCheck(check)
		return
	}

	// Get Satellite version from RPM
	versionCmd := "rpm -q satellite --queryformat '%{VERSION}'"
	versionOutput, err := utils.RunCommand("bash", "-c", versionCmd)
	versionString := strings.TrimSpace(versionOutput)

	if err != nil {
		// Try alternative package
		versionCmd = "rpm -q katello --queryformat '%{VERSION}'"
		versionOutput, err = utils.RunCommand("bash", "-c", versionCmd)
		versionString = strings.TrimSpace(versionOutput)

		if err != nil {
			check.Result = report.NewResult(report.StatusCritical,
				"Failed to determine Satellite version",
				report.ResultKeyRequired)
			report.AddRecommendation(&check.Result, "Verify that Red Hat Satellite is installed on this system.")
			report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_satellite/")
			r.AddCheck(check)
			return
		}
	}

	// Set the global version info
	satelliteVersionInfo.FullVersion = versionString

	// Determine Satellite major version
	satelliteMajorVersion := "0"
	if len(versionString) > 0 {
		parts := strings.Split(versionString, ".")
		if len(parts) > 0 {
			satelliteMajorVersion = parts[0]
			satelliteVersionInfo.MajorVersion = parts[0]
		}

		// Get minor version if available
		if len(parts) > 1 {
			satelliteVersionInfo.MinorVersion = parts[1]
		} else {
			satelliteVersionInfo.MinorVersion = "0"
		}
	}

	// Get installed RPMs for Satellite components
	satelliteRPMsCmd := "rpm -qa satellite\\* foreman\\* katello\\* --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'"
	satelliteRPMs, _ := utils.RunCommand("bash", "-c", satelliteRPMsCmd)

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("Satellite Version: %s\n\n", versionString))

	detail.WriteString("Installed Satellite RPMs:\n")
	detail.WriteString("[source, bash]\n----\n")
	// If output is very long, just show the first 20 lines
	if strings.Count(satelliteRPMs, "\n") > 20 {
		lines := strings.SplitN(satelliteRPMs, "\n", 21)
		satelliteRPMs = strings.Join(lines[:20], "\n") + "\n...(truncated)..."
	}
	detail.WriteString(satelliteRPMs)
	detail.WriteString("\n----\n\n")

	// Get service status for key Satellite services
	detail.WriteString("Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")

	services := []string{"postgresql", "httpd", "foreman", "foreman-proxy"}
	for _, service := range services {
		statusCmd := fmt.Sprintf("systemctl is-active %s", service)
		statusOutput, _ := utils.RunCommand("bash", "-c", statusCmd)
		detail.WriteString(fmt.Sprintf("- %s: %s\n", service, strings.TrimSpace(statusOutput)))
	}
	detail.WriteString("----\n\n")

	// Check if Satellite version is supported based on Red Hat's lifecycle information
	// Reference: https://access.redhat.com/support/policy/updates/satellite
	var lifecycleUrl string

	switch satelliteMajorVersion {
	case "6":
		minorVersion := "0"
		if len(versionString) > 2 {
			minorParts := strings.Split(versionString, ".")
			if len(minorParts) > 1 {
				minorVersion = minorParts[1]
			}
		}

		minorVersionNum := 0
		fmt.Sscanf(minorVersion, "%d", &minorVersionNum)

		// Documentation URL based on minor version
		if minorVersionNum >= 13 {
			lifecycleUrl = fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s", satelliteMajorVersion, minorVersion)
		} else {
			lifecycleUrl = "https://access.redhat.com/documentation/en-us/red_hat_satellite/6.13"
		}

		// Satellite 6.16 (Full support until approx May 2025)
		if minorVersionNum >= 16 {
			check.Result = report.NewResult(report.StatusOK,
				fmt.Sprintf("Satellite %s is installed and in full support", versionString),
				report.ResultKeyNoChange)
		} else if minorVersionNum == 15 {
			// Satellite 6.15 (Maintenance support until approx November 2025)
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Satellite %s is in maintenance support until approximately November 2025", versionString),
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Consider upgrading to Satellite 6.16 or newer for full support.")
		} else if minorVersionNum == 14 {
			// Satellite 6.14 (Maintenance support until May 30, 2025)
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Satellite %s is in maintenance support until May 30, 2025", versionString),
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Consider upgrading to Satellite 6.16 or newer for full support.")
		} else if minorVersionNum == 13 {
			// Satellite 6.13 (Maintenance support until November 30, 2024)
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Satellite %s is in maintenance support until November 30, 2024", versionString),
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Consider upgrading to Satellite 6.16 or newer for full support.")
		} else if minorVersionNum == 12 {
			// Satellite 6.12 (End of life May 31, 2024 - EOL)
			check.Result = report.NewResult(report.StatusCritical,
				fmt.Sprintf("Satellite %s reached end of life on May 31, 2024", versionString),
				report.ResultKeyRequired)
			report.AddRecommendation(&check.Result, "Upgrade to Satellite 6.16 or newer immediately as your version is no longer supported.")
		} else {
			// Older versions
			check.Result = report.NewResult(report.StatusCritical,
				fmt.Sprintf("Satellite %s is end of life", versionString),
				report.ResultKeyRequired)
			report.AddRecommendation(&check.Result, "Upgrade to Satellite 6.16 or newer immediately as your version is no longer supported.")
		}
	case "7":
		lifecycleUrl = "https://access.redhat.com/documentation/en-us/red_hat_satellite/7.0"
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Satellite %s is installed and supported", versionString),
			report.ResultKeyNoChange)
	default:
		lifecycleUrl = "https://access.redhat.com/documentation/en-us/red_hat_satellite/"
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Satellite version '%s' could not be verified", versionString),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify this is a supported Red Hat Satellite version.")
	}

	// Add reference link directly
	report.AddReferenceLink(&check.Result, lifecycleUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/support/policy/updates/satellite")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSatelliteServices checks the status of critical Satellite services
func checkSatelliteServices(r *report.AsciiDocReport) {
	checkID := "satellite-services"
	checkName := "Satellite Services"
	checkDesc := "Checks the status of critical Satellite services."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Use satellite-maintain service status to check services
	maintainCmd := "satellite-maintain service status"
	maintainOutput, err := utils.RunCommand("bash", "-c", maintainCmd)

	var detail strings.Builder
	detail.WriteString("Satellite Services Summary:\n\n")

	if err != nil {
		detail.WriteString("Error running satellite-maintain service status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Failed to get Satellite service status",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify 'satellite-maintain service status' is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	// If output is very long, just show the first 50 lines
	if strings.Count(maintainOutput, "\n") > 50 {
		lines := strings.SplitN(maintainOutput, "\n", 51)
		maintainOutput = strings.Join(lines[:50], "\n") + "\n...(truncated)..."
	}
	detail.WriteString(maintainOutput)
	detail.WriteString("\n----\n\n")

	// Parse the output to determine service status
	inactiveServices := []string{}
	disabledServices := []string{}

	// Extract services and their status
	serviceStatusMap := make(map[string]struct {
		Active  bool
		Enabled bool
	})

	// Extract service names from output
	serviceLines := extractServiceLines(maintainOutput)
	currentService := ""

	for _, line := range serviceLines {
		serviceName, isActive, isEnabled := parseServiceLine(line)
		if serviceName != "" {
			currentService = serviceName
			status := serviceStatusMap[currentService]
			status.Active = isActive
			status.Enabled = isEnabled
			serviceStatusMap[currentService] = status
		} else if currentService != "" && strings.Contains(line, "Active:") {
			status := serviceStatusMap[currentService]
			status.Active = strings.Contains(line, "active (running)")
			status.Enabled = strings.Contains(line, "enabled")
			serviceStatusMap[currentService] = status
		}
	}

	// Create a formatted table of services
	detail.WriteString("|===\n")
	detail.WriteString("| Service Name | Status | Boot Status \n\n")

	// Sort service names for consistent output
	var serviceNames []string
	for name := range serviceStatusMap {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, name := range serviceNames {
		status := serviceStatusMap[name]
		statusText := "Active"
		if !status.Active {
			statusText = "Inactive"
			inactiveServices = append(inactiveServices, name)
		}

		enabledText := "Enabled"
		if !status.Enabled {
			enabledText = "Disabled"
			disabledServices = append(disabledServices, name)
		}

		detail.WriteString(fmt.Sprintf("| %s | %s | %s \n", name, statusText, enabledText))
	}
	detail.WriteString("|===\n\n")

	// Add overall status
	detail.WriteString("\nOverall Status: ")
	if len(inactiveServices) == 0 && len(disabledServices) == 0 {
		detail.WriteString("All services are running and enabled\n")
	} else if len(inactiveServices) > 0 {
		detail.WriteString(fmt.Sprintf("%d services are not running\n", len(inactiveServices)))
	} else if len(disabledServices) > 0 {
		detail.WriteString(fmt.Sprintf("All services are running, but %d services are not enabled at boot\n", len(disabledServices)))
	}

	// Evaluate service status
	if len(inactiveServices) > 0 {
		severity := report.StatusWarning
		resultKey := report.ResultKeyRecommended

		// Critical services that should definitely be running
		mustRunServices := map[string]bool{
			"postgresql": true,
			"httpd":      true,
			"foreman":    true,
			"pulpcore":   true,
		}

		for _, service := range inactiveServices {
			for criticalService := range mustRunServices {
				if strings.Contains(service, criticalService) {
					severity = report.StatusCritical
					resultKey = report.ResultKeyRequired
					break
				}
			}
		}

		check.Result = report.NewResult(severity,
			fmt.Sprintf("%d Satellite services are not running", len(inactiveServices)),
			resultKey)

		for _, service := range inactiveServices {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Start '%s' service with 'systemctl start %s'", service, service))
		}

		if len(disabledServices) > 0 {
			for _, service := range disabledServices {
				report.AddRecommendation(&check.Result, fmt.Sprintf("Enable '%s' service with 'systemctl enable %s'", service, service))
			}
		}

		// Special recommendation for Satellite
		report.AddRecommendation(&check.Result, "You can also use 'satellite-maintain service start' to start all services.")
	} else if len(disabledServices) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"All Satellite services are running, but some are not enabled at boot",
			report.ResultKeyRecommended)

		for _, service := range disabledServices {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Enable '%s' service with 'systemctl enable %s'", service, service))
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All critical Satellite services are running and enabled",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_services",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// extractServiceLines extracts individual service entries from the satellite-maintain output
func extractServiceLines(maintainOutput string) []string {
	var serviceLines []string
	lines := strings.Split(maintainOutput, "\n")
	inServiceSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip blank lines
		if trimmedLine == "" {
			continue
		}

		// Service status starts with "- displaying"
		if strings.HasPrefix(trimmedLine, "- displaying") {
			inServiceSection = true
			serviceLines = append(serviceLines, trimmedLine)
			continue
		}

		// Service details lines that contain status information
		if inServiceSection && strings.Contains(trimmedLine, "Active:") {
			serviceLines = append(serviceLines, trimmedLine)
		}

		// End of services section
		if strings.Contains(trimmedLine, "All services are running") {
			inServiceSection = false
		}
	}

	return serviceLines
}

// parseServiceLine extracts service name and status from a service status line
func parseServiceLine(line string) (serviceName string, isActive bool, isEnabled bool) {
	// Handle lines that start with "- displaying"
	if strings.HasPrefix(line, "- displaying") {
		parts := strings.SplitN(line, "- displaying", 2)
		if len(parts) > 1 {
			serviceName = strings.TrimSpace(parts[1])
		}
		// Default to true for the initial line, actual status will be updated from Active: line
		return serviceName, true, true
	}

	// Handle lines with "Active:" status
	if strings.Contains(line, "Active:") {
		isActive = strings.Contains(line, "active (running)")
		isEnabled = strings.Contains(line, "enabled") && !strings.Contains(line, "disabled")
		return serviceName, isActive, isEnabled
	}

	return "", false, false
}

// checkSatelliteRegistration checks if the Satellite server is properly registered with Red Hat
func checkSatelliteRegistration(r *report.AsciiDocReport) {
	checkID := "satellite-registration"
	checkName := "Satellite Registration"
	checkDesc := "Ensures the Satellite server is properly registered with Red Hat."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check if system is registered
	identityCmd := "subscription-manager identity"
	identityOutput, err := utils.RunCommand("bash", "-c", identityCmd)

	var detail strings.Builder
	detail.WriteString("Subscription Status:\n\n")

	if err != nil {
		detail.WriteString("Error: System is not registered\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusCritical,
			"Satellite server is not registered with Red Hat Subscription Management",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Register the system using 'subscription-manager register'.")
		report.AddRecommendation(&check.Result, "Attach a Satellite subscription using 'subscription-manager attach'.")
	} else {
		detail.WriteString("Identity Information:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(identityOutput)
		detail.WriteString("\n----\n\n")

		// Get subscription status
		statusCmd := "subscription-manager status"
		statusOutput, _ := utils.RunCommand("bash", "-c", statusCmd)
		detail.WriteString("Subscription Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(statusOutput)
		detail.WriteString("\n----\n\n")

		// Check for attached subscriptions
		listCmd := "subscription-manager list --consumed"
		listOutput, _ := utils.RunCommand("bash", "-c", listCmd)
		detail.WriteString("Consumed Subscriptions:\n")
		detail.WriteString("[source, bash]\n----\n")
		// If output is very long, trim it to show just first part
		if strings.Count(listOutput, "\n") > 30 {
			lines := strings.SplitN(listOutput, "\n", 31)
			listOutput = strings.Join(lines[:30], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(listOutput)
		detail.WriteString("\n----\n\n")

		// Check if using Simple Content Access mode
		usingSCA := strings.Contains(statusOutput, "Content Access Mode is set to Simple Content Access") ||
			strings.Contains(statusOutput, "access to content, regardless of subscription status")

		// Determine if subscriptions are attached
		hasNoSubscriptions := strings.Contains(listOutput, "No consumed subscription") ||
			strings.Contains(listOutput, "No consumed subscription pools were found")

		// Check for Satellite subscription
		hasSatelliteSub := strings.Contains(strings.ToLower(listOutput), "satellite")

		if hasNoSubscriptions && !usingSCA {
			check.Result = report.NewResult(report.StatusCritical,
				"Satellite server is registered but has no subscriptions attached",
				report.ResultKeyRequired)
			report.AddRecommendation(&check.Result, "Attach a subscription using 'subscription-manager attach'.")
		} else if !hasSatelliteSub && !usingSCA {
			check.Result = report.NewResult(report.StatusWarning,
				"System is registered but may not have a Satellite subscription attached",
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Verify that a proper Satellite subscription is attached.")
			report.AddRecommendation(&check.Result, "Use 'subscription-manager list --available' to see available subscriptions.")
		} else if usingSCA {
			check.Result = report.NewResult(report.StatusOK,
				"Satellite server is properly registered with Red Hat using Simple Content Access mode",
				report.ResultKeyNoChange)
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"Satellite server is properly registered with Red Hat",
				report.ResultKeyNoChange)
		}
	}

	// Add reference link directly
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_satellite_server_from_a_connected_network/preparing_your_environment_for_installation",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/subscription_central/2024/html/using_red_hat_subscription_management/")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSatelliteRepositories validates that required repositories are enabled for Satellite
func checkSatelliteRepositories(r *report.AsciiDocReport) {
	checkID := "satellite-repos"
	checkName := "Satellite Repositories"
	checkDesc := "Validates that required Satellite repositories are enabled."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of repositories
	repoCmd := "dnf repolist enabled 2>/dev/null || subscription-manager repos --list-enabled"
	repoOutput, err := utils.RunCommand("bash", "-c", repoCmd)

	var detail strings.Builder
	detail.WriteString("Enabled Repositories:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving repository information:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Failed to get repository information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify that subscription-manager is working properly.")
		report.AddRecommendation(&check.Result, "Check if the system is registered with Red Hat.")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_satellite_server_from_a_connected_network/preparing_your_environment_for_installation",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	// If output is very long, trim it to show just the first part
	if strings.Count(repoOutput, "\n") > 40 {
		lines := strings.SplitN(repoOutput, "\n", 41)
		repoOutput = strings.Join(lines[:40], "\n") + "\n...(truncated)..."
	}
	detail.WriteString(repoOutput)
	detail.WriteString("\n----\n\n")

	// Get RHEL version
	rhelVersionCmd := "cat /etc/redhat-release"
	rhelVersionOutput, _ := utils.RunCommand("bash", "-c", rhelVersionCmd)
	rhelVersionString := strings.TrimSpace(rhelVersionOutput)

	// Get Satellite version
	versionInfo := GetSatelliteVersion()
	versionString := versionInfo.FullVersion

	// Determine Satellite major version
	satelliteMajorVersion := versionInfo.MajorVersion

	// Determine RHEL major version
	rhelMajorVersion := "0"
	if strings.Contains(rhelVersionString, "8.") {
		rhelMajorVersion = "8"
	} else if strings.Contains(rhelVersionString, "9.") {
		rhelMajorVersion = "9"
	}

	// Define the required repositories based on Satellite version and RHEL version
	var requiredRepos []string

	if rhelMajorVersion == "8" {
		requiredRepos = []string{
			"rhel-8-for-x86_64-baseos-rpms",
			"rhel-8-for-x86_64-appstream-rpms",
		}

		// Add version-specific repo
		if satelliteMajorVersion == "6" {
			if strings.HasPrefix(versionString, "6.12") {
				requiredRepos = append(requiredRepos, "satellite-6.12-for-rhel-8-x86_64-rpms")
				requiredRepos = append(requiredRepos, "satellite-maintenance-6.12-for-rhel-8-x86_64-rpms")
			} else if strings.HasPrefix(versionString, "6.13") {
				requiredRepos = append(requiredRepos, "satellite-6.13-for-rhel-8-x86_64-rpms")
				requiredRepos = append(requiredRepos, "satellite-maintenance-6.13-for-rhel-8-x86_64-rpms")
			} else if strings.HasPrefix(versionString, "6.14") {
				requiredRepos = append(requiredRepos, "satellite-6.14-for-rhel-8-x86_64-rpms")
				requiredRepos = append(requiredRepos, "satellite-maintenance-6.14-for-rhel-8-x86_64-rpms")
			} else {
				requiredRepos = append(requiredRepos, "satellite-6-for-rhel-8-x86_64-rpms")
				requiredRepos = append(requiredRepos, "satellite-maintenance-6-for-rhel-8-x86_64-rpms")
			}
		} else if satelliteMajorVersion == "7" {
			requiredRepos = append(requiredRepos, "satellite-7-for-rhel-8-x86_64-rpms")
		}
	} else if rhelMajorVersion == "9" {
		requiredRepos = []string{
			"rhel-9-for-x86_64-baseos-rpms",
			"rhel-9-for-x86_64-appstream-rpms",
		}

		// Add version-specific repo for RHEL 9
		if satelliteMajorVersion == "6" && strings.HasPrefix(versionString, "6.14") {
			requiredRepos = append(requiredRepos, "satellite-6.14-for-rhel-9-x86_64-rpms")
			requiredRepos = append(requiredRepos, "satellite-maintenance-6.14-for-rhel-9-x86_64-rpms")
		} else if satelliteMajorVersion == "7" {
			requiredRepos = append(requiredRepos, "satellite-7-for-rhel-9-x86_64-rpms")
		}
	}

	// Check if required repos are enabled
	var missingRepos []string
	for _, repo := range requiredRepos {
		if !containsRepository(repoOutput, repo) {
			missingRepos = append(missingRepos, repo)
		}
	}

	detail.WriteString(fmt.Sprintf("RHEL Version: %s\n", rhelMajorVersion))
	detail.WriteString(fmt.Sprintf("Satellite Version: %s\n", versionString))
	detail.WriteString("\nRequired Repositories:\n")
	for _, repo := range requiredRepos {
		detail.WriteString(fmt.Sprintf("- %s\n", repo))
	}

	if len(missingRepos) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Missing %d required Satellite repositories", len(missingRepos)),
			report.ResultKeyRecommended)

		for _, repo := range missingRepos {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Enable the '%s' repository using 'subscription-manager repos --enable=%s'.", repo, repo))
		}
	} else if len(requiredRepos) > 0 {
		check.Result = report.NewResult(report.StatusOK,
			"All required Satellite repositories are enabled",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine required repositories for this Satellite version",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Ensure appropriate repositories for your Satellite version are enabled.")
	}

	// Add reference link
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_satellite_server_from_a_connected_network/preparing_your_environment_for_installation#enabling-repositories_satellite",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// containsRepository checks if a repository is in the enabled repos output
func containsRepository(repoOutput string, repoName string) bool {
	// Check for direct match or repo id entry
	return strings.Contains(repoOutput, repoName) ||
		strings.Contains(repoOutput, "repo id") && strings.Contains(repoOutput, repoName)
}

// Helper function to convert bool to Yes/No
//func boolToYesNo(value bool) string {
//	if value {
//		return "Yes"
//	}
//	return "No"
//}
