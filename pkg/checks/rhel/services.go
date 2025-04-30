// pkg/checks/rhel/services.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunServicesChecks performs service related checks
func RunServicesChecks(r *report.AsciiDocReport) {
	// Identify and recommend disabling unnecessary services
	checkUnnecessaryServices(r)

	// Confirm required services are enabled and active
	checkRequiredServices(r)

	// Review systemd default boot target
	checkBootTarget(r)

	// Ensure clean system boot without errors
	checkBootErrors(r)
}

// checkUnnecessaryServices identifies and recommends disabling unnecessary services
func checkUnnecessaryServices(r *report.AsciiDocReport) {
	checkID := "services-unnecessary"
	checkName := "Unnecessary Services"
	checkDesc := "Identifies and recommends disabling unnecessary services."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Get list of all services - removed unused servicesOutput variable
	servicesCmd := "systemctl list-units --type=service --all"
	_, err := utils.RunCommand("bash", "-c", servicesCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to list services", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure systemd is properly working.")
		r.AddCheck(check)
		return
	}

	// Get list of enabled services - removed unused enabledOutput variable
	enabledCmd := "systemctl list-unit-files --type=service --state=enabled"
	_, _ = utils.RunCommand("bash", "-c", enabledCmd)

	// List of potentially unnecessary services that should be reviewed
	unnecessaryServices := []string{
		"avahi-daemon",
		"cups",
		"isc-dhcp-server",
		"nfs-server",
		"rpcbind",
		"telnet",
		"vsftpd",
		"xinetd",
		"bluetooth",
		"rsh",
		"ypbind",
	}

	// Find running unnecessary services
	runningUnnecessary := []string{}
	for _, service := range unnecessaryServices {
		// Check if service is running
		runningCmd := fmt.Sprintf("systemctl is-active %s.service 2>/dev/null || echo 'inactive'", service)
		runningOutput, _ := utils.RunCommand("bash", "-c", runningCmd)
		runningOutput = strings.TrimSpace(runningOutput)

		// Check if service is enabled
		enabledCmd := fmt.Sprintf("systemctl is-enabled %s.service 2>/dev/null || echo 'disabled'", service)
		enabledOutput, _ := utils.RunCommand("bash", "-c", enabledCmd)
		enabledOutput = strings.TrimSpace(enabledOutput)

		if runningOutput == "active" || enabledOutput == "enabled" {
			runningUnnecessary = append(runningUnnecessary, service)
		}
	}

	// Get TCP listening ports to identify other services
	listeningPortsCmd := "ss -tulnp"
	listeningPortsOutput, _ := utils.RunCommand("bash", "-c", listeningPortsCmd)

	var detail strings.Builder
	detail.WriteString("List of Potentially Unnecessary Services:\n")
	detail.WriteString("[source, bash]\n----\n")
	for _, service := range unnecessaryServices {
		statusCmd := fmt.Sprintf("systemctl status %s.service 2>/dev/null || echo 'not found'", service)
		statusOutput, _ := utils.RunCommand("bash", "-c", statusCmd)

		if !strings.Contains(statusOutput, "not found") {
			detail.WriteString(fmt.Sprintf("\n--- %s ---\n", service))
			detail.WriteString(statusOutput)
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Listening Services and Ports:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(listeningPortsOutput)
	detail.WriteString("\n----\n")

	// Evaluate unnecessary services
	if len(runningUnnecessary) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d potentially unnecessary services running", len(runningUnnecessary)),
			report.ResultKeyRecommended)

		for _, service := range runningUnnecessary {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Consider disabling '%s' if not needed", service))
		}

		report.AddRecommendation(&check.Result, "To disable a service: 'systemctl disable <service>.service'")
		report.AddRecommendation(&check.Result, "To stop a service: 'systemctl stop <service>.service'")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/using_systemd_unit_files_to_customize_and_optimize_your_system/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No unnecessary services were identified",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRequiredServices confirms required services are enabled and active
func checkRequiredServices(r *report.AsciiDocReport) {
	checkID := "services-required"
	checkName := "Required Services"
	checkDesc := "Confirms required services are enabled and active."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// List of required services for a typical RHEL system
	requiredServices := []string{
		"sshd",
		"chronyd",
		"auditd",
		"rsyslog",
		"crond",
		"firewalld",
	}

	// Check the status of each required service
	inactiveServices := []string{}
	disabledServices := []string{}

	var detail strings.Builder
	detail.WriteString("Status of Required Services:\n")
	detail.WriteString("[source, bash]\n----\n")

	for _, service := range requiredServices {
		// Check if service is running
		runningCmd := fmt.Sprintf("systemctl is-active %s.service 2>/dev/null || echo 'inactive'", service)
		runningOutput, _ := utils.RunCommand("bash", "-c", runningCmd)
		runningOutput = strings.TrimSpace(runningOutput)

		// Check if service is enabled
		enabledCmd := fmt.Sprintf("systemctl is-enabled %s.service 2>/dev/null || echo 'disabled'", service)
		enabledOutput, _ := utils.RunCommand("bash", "-c", enabledCmd)
		enabledOutput = strings.TrimSpace(enabledOutput)

		detail.WriteString(fmt.Sprintf("%s: Status=%s, Boot=%s\n", service, runningOutput, enabledOutput))

		if runningOutput != "active" {
			inactiveServices = append(inactiveServices, service)
		}

		if enabledOutput != "enabled" && enabledOutput != "enabled-runtime" {
			disabledServices = append(disabledServices, service)
		}
	}
	detail.WriteString("\n----\n\n")

	// Get all services
	allServicesCmd := "systemctl --type=service --state=active"
	allServicesOutput, _ := utils.RunCommand("bash", "-c", allServicesCmd)

	detail.WriteString("All Active Services:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(allServicesOutput)
	detail.WriteString("\n----\n")

	// Evaluate required services
	if len(inactiveServices) > 0 || len(disabledServices) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found issues with %d required services", len(inactiveServices)+len(disabledServices)),
			report.ResultKeyRecommended)

		for _, service := range inactiveServices {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Start service '%s': 'systemctl start %s'", service, service))
		}

		for _, service := range disabledServices {
			if !containsString(inactiveServices, service) {
				report.AddRecommendation(&check.Result, fmt.Sprintf("Enable service '%s' at boot: 'systemctl enable %s'", service, service))
			} else {
				report.AddRecommendation(&check.Result, fmt.Sprintf("Enable and start service '%s': 'systemctl enable --now %s'", service, service))
			}
		}

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/using_systemd_unit_files_to_customize_and_optimize_your_system/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All required services are active and enabled",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// containsString checks if a string is present in a slice of strings
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// checkBootTarget reviews systemd default boot target
func checkBootTarget(r *report.AsciiDocReport) {
	checkID := "boot-target"
	checkName := "Boot Target"
	checkDesc := "Reviews systemd default boot target."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Get default target
	defaultTargetCmd := "systemctl get-default"
	defaultTargetOutput, err := utils.RunCommand("bash", "-c", defaultTargetCmd)
	defaultTarget := strings.TrimSpace(defaultTargetOutput)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine default boot target", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check systemd configuration.")
		r.AddCheck(check)
		return
	}

	// Get list of available targets
	availableTargetsCmd := "find /lib/systemd/system /etc/systemd/system -name '*.target' | grep -v wants | grep -v requires"
	availableTargetsOutput, _ := utils.RunCommand("bash", "-c", availableTargetsCmd)

	// Check if X11 packages are installed (for GUI)
	guiPackagesCmd := "rpm -qa | grep -E '(x11|gnome|kde|xorg)' | wc -l"
	guiPackagesOutput, _ := utils.RunCommand("bash", "-c", guiPackagesCmd)
	guiPackagesCount := strings.TrimSpace(guiPackagesOutput)

	hasGUI := false
	guiPackagesNum := 0
	if count, err := fmt.Sscanf(guiPackagesCount, "%d", &guiPackagesNum); err == nil && count > 0 && guiPackagesNum > 0 {
		hasGUI = true
	}

	// Check if this is a server role
	isServerRole := true

	// Simple heuristic - check for server-related packages
	serverRoleCmd := "rpm -qa | grep -E '(httpd|nginx|postgresql|mariadb|mysql|docker|podman|tomcat|jenkins|oracle)' | wc -l"
	serverRoleOutput, _ := utils.RunCommand("bash", "-c", serverRoleCmd)
	serverCount := 0
	fmt.Sscanf(strings.TrimSpace(serverRoleOutput), "%d", &serverCount)

	if serverCount > 0 {
		isServerRole = true
	}

	var detail strings.Builder
	detail.WriteString("Boot Target Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Default Boot Target: %s\n", defaultTarget))
	detail.WriteString(fmt.Sprintf("GUI Packages Installed: %v (found %d packages)\n", hasGUI, guiPackagesNum))
	detail.WriteString(fmt.Sprintf("Server Role Detected: %v (found %d server packages)\n", isServerRole, serverCount))
	detail.WriteString("\n----\n\n")

	detail.WriteString("Available Targets:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(availableTargetsOutput)
	detail.WriteString("\n----\n")

	// Evaluate boot target based on RHEL best practices
	if defaultTarget == "graphical.target" {
		if isServerRole {
			// For server roles, graphical target is almost always not recommended
			check.Result = report.NewResult(report.StatusWarning,
				"Default boot target is graphical.target but system appears to be a server",
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "RHEL best practice for servers is to use minimal installation without GUI")
			report.AddRecommendation(&check.Result, "Change boot target: 'systemctl set-default multi-user.target'")
			report.AddRecommendation(&check.Result, "Consider removing unnecessary GUI packages to reduce attack surface and resource usage")
		} else if !hasGUI {
			// Graphical target but no GUI packages - this is a misconfiguration
			check.Result = report.NewResult(report.StatusWarning,
				"Default boot target is graphical but no GUI packages installed",
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "Change boot target: 'systemctl set-default multi-user.target'")
		} else {
			// Has GUI packages, but still recommend text mode for RHEL best practices
			check.Result = report.NewResult(report.StatusWarning,
				"Using graphical.target for boot - consider using text mode for RHEL systems",
				report.ResultKeyRecommended)
			report.AddRecommendation(&check.Result, "RHEL best practice is to use minimal installation with text mode")
			report.AddRecommendation(&check.Result, "For non-desktop systems, consider 'systemctl set-default multi-user.target'")
		}

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/using_systemd_unit_files_to_customize_and_optimize_your_system/index", rhelVersion))
	} else if defaultTarget != "multi-user.target" {
		// Non-standard targets are generally not recommended
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Unusual default boot target: %s", defaultTarget),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify this target is appropriate for your use case")
		report.AddRecommendation(&check.Result, "RHEL best practice is to use multi-user.target (text mode)")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/using_systemd_unit_files_to_customize_and_optimize_your_system/index", rhelVersion))
	} else {
		// multi-user.target is the recommended setting
		check.Result = report.NewResult(report.StatusOK,
			"Default boot target is multi-user.target (text mode), following RHEL best practices",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkBootErrors ensures clean system boot without errors
func checkBootErrors(r *report.AsciiDocReport) {
	checkID := "boot-errors"
	checkName := "Boot Errors"
	checkDesc := "Ensures clean system boot without errors."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check systemd journal for boot errors
	bootErrorsCmd := "journalctl -p 0..3 -b | grep -v firewalld | grep -v 'duplicated line'"
	bootErrorsOutput, err := utils.RunCommand("bash", "-c", bootErrorsCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to check boot errors", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure journalctl is available.")
		r.AddCheck(check)
		return
	}

	// Check for failed units
	failedUnitsCmd := "systemctl --failed"
	failedUnitsOutput, _ := utils.RunCommand("bash", "-c", failedUnitsCmd)

	// Check kernel messages
	dmesgErrorsCmd := "dmesg | grep -iE '(error|fail|critical)'"
	dmesgErrorsOutput, _ := utils.RunCommand("bash", "-c", dmesgErrorsCmd)

	var detail strings.Builder
	detail.WriteString("Boot Error Messages:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(bootErrorsOutput) == "" {
		detail.WriteString("No boot errors found in journal\n")
	} else {
		// Only show the first 20 lines if there are many errors
		lines := strings.Split(bootErrorsOutput, "\n")
		if len(lines) > 20 {
			detail.WriteString(strings.Join(lines[:20], "\n"))
			detail.WriteString("\n... (output truncated, showing first 20 lines out of " + fmt.Sprintf("%d", len(lines)) + ")\n")
		} else {
			detail.WriteString(bootErrorsOutput)
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Failed Units:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(failedUnitsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kernel Error Messages:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(dmesgErrorsOutput) == "" {
		detail.WriteString("No critical kernel errors found\n")
	} else {
		// Only show the first 20 lines if there are many errors
		lines := strings.Split(dmesgErrorsOutput, "\n")
		if len(lines) > 20 {
			detail.WriteString(strings.Join(lines[:20], "\n"))
			detail.WriteString("\n... (output truncated, showing first 20 lines out of " + fmt.Sprintf("%d", len(lines)) + ")\n")
		} else {
			detail.WriteString(dmesgErrorsOutput)
		}
	}
	detail.WriteString("\n----\n")

	// Count error lines
	errorCount := 0
	if strings.TrimSpace(bootErrorsOutput) != "" {
		errorCount += len(strings.Split(bootErrorsOutput, "\n"))
	}

	// Count failed units
	failedUnitsCount := 0
	if strings.Contains(failedUnitsOutput, ".service") {
		for _, line := range strings.Split(failedUnitsOutput, "\n") {
			if strings.Contains(line, "UNIT") || strings.Contains(line, "LOAD") {
				continue // Skip header lines
			}
			if strings.Contains(line, ".service") {
				failedUnitsCount++
			}
		}
	}

	// Evaluate boot errors
	if errorCount > 0 || failedUnitsCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d boot errors and %d failed units", errorCount, failedUnitsCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review boot errors with 'journalctl -p 0..3 -b'")
		report.AddRecommendation(&check.Result, "Check failed services with 'systemctl --failed'")
		report.AddRecommendation(&check.Result, "Investigate and resolve service failures")

		// Add RHEL documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/assembly_troubleshooting-problems-using-log-files_configuring-basic-system-settings", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No boot errors or failed services detected",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
