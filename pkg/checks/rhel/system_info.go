// pkg/checks/rhel/system_info.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunSystemInfoChecks performs system information related checks
func RunSystemInfoChecks(r *report.AsciiDocReport) {
	// System hostname
	checkSystemHostname(r)

	// RHEL version
	checkRHELVersion(r)

	// System uptime
	checkSystemUptime(r)

	// System registration
	checkSystemRegistration(r)

	// Required repositories
	checkRepositories(r)
}

// checkSystemHostname checks the system hostname and ensures it matches DNS
func checkSystemHostname(r *report.AsciiDocReport) {
	checkID := "system-hostname"
	checkName := "System Hostname"
	checkDesc := "Verifies system hostname and ensures it matches DNS."

	// Create the check
	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Get hostname
	hostname, err := utils.RunCommand("hostname")
	hostname = strings.TrimSpace(hostname)

	if err != nil {
		check.Result = report.NewResult(report.StatusCritical,
			"Failed to get system hostname", report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Check if the hostname command is available and working properly.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/getting-started-with-rhel-networking_configuring-and-managing-networking", rhelVersion))
		r.AddCheck(check)
		return
	}

	// Get FQDN
	fqdn, err := utils.RunCommand("hostname", "-f")
	fqdn = strings.TrimSpace(fqdn)
	if err != nil {
		fqdn = hostname
	}

	// Check if hostname resolves
	_, err = utils.RunCommand("getent", "hosts", fqdn)

	var detail strings.Builder
	detail.WriteString("Hostname Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	detail.WriteString(fmt.Sprintf("FQDN: %s\n", fqdn))
	detail.WriteString("----\n\n")

	if err != nil {
		// Hostname doesn't resolve
		dnsCheckOutput, _ := utils.RunCommand("getent", "hosts", fqdn)
		detail.WriteString("DNS Lookup Result:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(dnsCheckOutput)
		detail.WriteString("\n----\n")

		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Hostname '%s' doesn't resolve in DNS", fqdn),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the hostname is properly configured in DNS.")
		report.AddRecommendation(&check.Result, "Update /etc/hosts with the correct entry if DNS update is not possible.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/using-and-configuring-the-resolver_configuring-and-managing-networking", rhelVersion))
	} else {
		// Hostname resolves - good!
		lookup, _ := utils.RunCommand("getent", "hosts", fqdn)
		detail.WriteString("DNS Lookup Result:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(lookup)
		detail.WriteString("\n----\n")

		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Hostname '%s' resolves correctly", fqdn),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRHELVersion checks if the correct RHEL version is installed
func checkRHELVersion(r *report.AsciiDocReport) {
	checkID := "rhel-version"
	checkName := "RHEL Version"
	checkDesc := "Confirms the correct RHEL version is installed."

	// Get RHEL version
	versionOutput, err := utils.RunCommand("cat", "/etc/redhat-release")
	versionString := strings.TrimSpace(versionOutput)

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	if err != nil {
		check.Result = report.NewResult(report.StatusCritical,
			"Failed to determine RHEL version", report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Check if this is a Red Hat Enterprise Linux system.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/")
		r.AddCheck(check)
		return
	}

	// Get kernel version
	kernelVersion, err := utils.RunCommand("uname", "-r")
	kernelVersion = strings.TrimSpace(kernelVersion)
	if err != nil {
		kernelVersion = "Unknown"
	}

	var detail strings.Builder
	detail.WriteString("RHEL Version Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("RHEL Version: %s\n", versionString))
	detail.WriteString(fmt.Sprintf("Kernel Version: %s\n", kernelVersion))
	detail.WriteString("\n----\n\n")

	// Get more details from os-release
	osReleaseOutput, err := utils.RunCommand("cat", "/etc/os-release")
	if err == nil {
		detail.WriteString("OS Release Information:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(osReleaseOutput)
		detail.WriteString("\n----\n")
	}

	// Determine RHEL major version
	rhelMajorVersion := "0"
	if strings.Contains(versionString, "7.") {
		rhelMajorVersion = "7"
	} else if strings.Contains(versionString, "8.") {
		rhelMajorVersion = "8"
	} else if strings.Contains(versionString, "9.") {
		rhelMajorVersion = "9"
	}

	// Check if RHEL version is supported
	switch rhelMajorVersion {
	case "8", "9":
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("RHEL %s is installed and supported", rhelMajorVersion),
			report.ResultKeyNoChange)
	case "7":
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("RHEL 7 is approaching end of life: %s", versionString),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider upgrading to a supported RHEL version (8 or 9).")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/")
	default:
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("RHEL version could not be verified: %s", versionString),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify this is a supported Red Hat Enterprise Linux version.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/support/policy/updates/errata")
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSystemUptime checks the system uptime and identifies unexpected reboots
func checkSystemUptime(r *report.AsciiDocReport) {
	checkID := "system-uptime"
	checkName := "System Uptime"
	checkDesc := "Checks system uptime and identifies any unexpected reboots."

	// Get uptime information
	uptimeOutput, err := utils.RunCommand("uptime")
	uptimeOutput = strings.TrimSpace(uptimeOutput)

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to get system uptime", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if the 'uptime' command is available.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_monitoring_and_updating_the_kernel/setting-up-kernel-crash-dump-mechanism_managing-monitoring-and-updating-the-kernel", rhelVersion))
		r.AddCheck(check)
		return
	}

	// Additional uptime information with -s flag (start time)
	startTimeOutput, _ := utils.RunCommand("uptime", "-s")
	startTimeOutput = strings.TrimSpace(startTimeOutput)

	// Get last reboot information
	lastRebootCmd := "last reboot | head -3"
	lastRebootOutput, _ := utils.RunCommand("bash", "-c", lastRebootCmd)

	var detail strings.Builder
	detail.WriteString("System Uptime Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Current Uptime: %s\n", uptimeOutput))
	if startTimeOutput != "" {
		detail.WriteString(fmt.Sprintf("System Start Time: %s\n", startTimeOutput))
	}
	detail.WriteString("----\n\n")

	detail.WriteString("Last Reboot Events:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(lastRebootOutput)
	detail.WriteString("\n----\n")

	// Try to parse uptime in days
	uptimeDays := 0
	if strings.Contains(uptimeOutput, "day") {
		parts := strings.SplitN(uptimeOutput, "up", 2)
		if len(parts) > 1 {
			uptimePart := parts[1]
			dayParts := strings.SplitN(uptimePart, "day", 2)
			if len(dayParts) > 1 {
				dayValue := strings.TrimSpace(dayParts[0])
				fmt.Sscanf(dayValue, "%d", &uptimeDays)
			}
		}
	}

	// Evaluate uptime
	if uptimeDays > 365 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("System uptime is very high (%d days)", uptimeDays),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider scheduling a maintenance window to apply updates and reboot.")
		report.AddRecommendation(&check.Result, "Long uptimes may indicate missing security patches and updates.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-system-updates_configuring-basic-system-settings", rhelVersion))
	} else if uptimeDays < 1 {
		check.Result = report.NewResult(report.StatusWarning,
			"System was recently rebooted (less than 1 day ago)",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Check system logs to verify if the recent reboot was planned or unexpected.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/logging_and_monitoring/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("System uptime is %d days", uptimeDays),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSystemRegistration checks if the system is properly registered with Red Hat
func checkSystemRegistration(r *report.AsciiDocReport) {
	checkID := "system-registration"
	checkName := "System Registration"
	checkDesc := "Ensures system is properly registered with Red Hat."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Check if subscription-manager is available
	_, err := utils.RunCommand("which", "subscription-manager")
	if err != nil {
		check.Result = report.NewResult(report.StatusCritical,
			"subscription-manager not found",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Install subscription-manager package.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_logical_volumes/assembly_registering-your-system-by-using-subscription-manager_configuring-and-managing-logical-volumes", rhelVersion))
		r.AddCheck(check)
		return
	}

	// Get identity information
	identityOutput, err := utils.RunCommand("subscription-manager", "identity")

	var detail strings.Builder
	detail.WriteString("Identity Information:\n")
	detail.WriteString("[source, bash]\n----\n")

	if err != nil {
		detail.WriteString("Error: System is not registered\n")
		detail.WriteString(err.Error())
	} else {
		detail.WriteString(identityOutput)
	}
	detail.WriteString("----\n\n")

	// Get subscription status if system is registered
	if err == nil {
		statusOutput, _ := utils.RunCommand("subscription-manager", "status")
		detail.WriteString("Subscription Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(statusOutput)
		detail.WriteString("----\n\n")

		// Check for attached subscriptions
		listOutput, _ := utils.RunCommand("subscription-manager", "list", "--consumed")
		detail.WriteString("Consumed Subscriptions:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(listOutput)
		detail.WriteString("\n----\n")

		// Check if using Simple Content Access mode
		usingSCA := strings.Contains(statusOutput, "Content Access Mode is set to Simple Content Access") ||
			strings.Contains(statusOutput, "access to content, regardless of subscription status")

		// Determine if subscriptions are attached
		hasNoSubscriptions := strings.Contains(listOutput, "No consumed subscription") ||
			strings.Contains(listOutput, "No consumed subscription pools were found")

		if hasNoSubscriptions && !usingSCA {
			check.Result = report.NewResult(report.StatusCritical,
				"System is registered but has no subscriptions attached",
				report.ResultKeyRequired)
			report.AddRecommendation(&check.Result, "Attach a subscription using 'subscription-manager attach'.")

			// Add reference link directly
			rhelVersion := utils.GetRedHatVersion()
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-system-registration-and-certificates_configuring-basic-system-settings", rhelVersion))
		} else if usingSCA {
			check.Result = report.NewResult(report.StatusOK,
				"System is properly registered with Red Hat using Simple Content Access mode",
				report.ResultKeyNoChange)
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"System is properly registered with Red Hat",
				report.ResultKeyNoChange)
		}
	} else {
		check.Result = report.NewResult(report.StatusCritical,
			"System is not registered with Red Hat Subscription Management",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Register the system using 'subscription-manager register'.")
		report.AddRecommendation(&check.Result, "Attach a subscription using 'subscription-manager attach'.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-system-registration-and-certificates_configuring-basic-system-settings", rhelVersion))
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRepositories validates that required repositories are enabled
func checkRepositories(r *report.AsciiDocReport) {
	checkID := "enabled-repos"
	checkName := "Enabled Repositories"
	checkDesc := "Validates that required repositories are enabled."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Get list of repositories
	repoOutput, err := utils.RunCommand("subscription-manager", "repos", "--list-enabled")

	var detail strings.Builder
	detail.WriteString("Enabled Repositories:\n")
	detail.WriteString("[source, bash]\n----\n")

	if err != nil {
		detail.WriteString("Error retrieving repository information:\n")
		detail.WriteString(err.Error())
	} else {
		detail.WriteString(repoOutput)
	}
	detail.WriteString("----\n\n")

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to get repository information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify that subscription-manager is working properly.")
		report.AddRecommendation(&check.Result, "Check if the system is registered with Red Hat.")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-software-packages_configuring-basic-system-settings", rhelVersion))
		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	// Get RHEL version
	rhelVersionCmd := "cat /etc/redhat-release"
	rhelVersionOutput, _ := utils.RunCommand("bash", "-c", rhelVersionCmd)
	rhelVersionString := strings.TrimSpace(rhelVersionOutput)

	detail.WriteString("RHEL Version:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rhelVersionString)
	detail.WriteString("\n----\n")

	// Determine RHEL major version
	rhelMajorVersion := "0"
	if strings.Contains(rhelVersionString, "7.") {
		rhelMajorVersion = "7"
	} else if strings.Contains(rhelVersionString, "8.") {
		rhelMajorVersion = "8"
	} else if strings.Contains(rhelVersionString, "9.") {
		rhelMajorVersion = "9"
	}

	// Check for required repositories based on RHEL version
	var requiredRepos []string
	var missingRepos []string

	switch rhelMajorVersion {
	case "7":
		requiredRepos = []string{"rhel-7-server-rpms"}
	case "8":
		requiredRepos = []string{"rhel-8-for-x86_64-baseos-rpms", "rhel-8-for-x86_64-appstream-rpms"}
	case "9":
		requiredRepos = []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"}
	}

	// Check if required repos are enabled
	for _, repo := range requiredRepos {
		if !strings.Contains(repoOutput, repo) {
			missingRepos = append(missingRepos, repo)
		}
	}

	if len(missingRepos) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Missing %d required repositories", len(missingRepos)),
			report.ResultKeyRecommended)

		for _, repo := range missingRepos {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Enable the '%s' repository using 'subscription-manager repos --enable=%s'.", repo, repo))
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-software-packages_configuring-basic-system-settings", rhelMajorVersion))
	} else if len(requiredRepos) > 0 {
		check.Result = report.NewResult(report.StatusOK,
			"All required repositories are enabled",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine required repositories for this RHEL version",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Ensure appropriate repositories are enabled for your RHEL version.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/")
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
