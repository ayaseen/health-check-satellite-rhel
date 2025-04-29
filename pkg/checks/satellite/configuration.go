// pkg/checks/satellite/configuration.go

package satellite

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunConfigurationChecks performs Satellite configuration checks
func RunConfigurationChecks(r *report.AsciiDocReport) {
	// Check Satellite settings
	checkSatelliteSettings(r)

	// Check installer configuration
	checkInstallerConfig(r)

}

// checkSatelliteSettings checks Satellite application settings
func checkSatelliteSettings(r *report.AsciiDocReport) {
	checkID := "satellite-settings"
	checkName := "Satellite Settings"
	checkDesc := "Validates Satellite application settings."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get all Satellite settings
	settingsCmd := "hammer settings list"
	settingsOutput, err := utils.RunCommand("bash", "-c", settingsCmd)

	var detail strings.Builder
	detail.WriteString("Satellite Settings Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving Satellite settings:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve Satellite settings",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/chap-red_hat_satellite-administering_red_hat_satellite-configuring_settings",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("All Satellite Settings (sample):\n\n")
	// Only show the first part to avoid extremely long output
	settingsLines := strings.Split(settingsOutput, "\n")
	if len(settingsLines) > 30 {
		detail.WriteString("[source, text]\n----\n")
		for i := 0; i < 30; i++ {
			detail.WriteString(settingsLines[i] + "\n")
		}
		detail.WriteString("... (output truncated for brevity) ...\n")
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(settingsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check important settings
	criticalSettings := []string{
		"trusted_puppetmaster_hosts",
		"unattended_url",
		"login_delegation_logout_url",
		"websockets_encrypt",
		"remote_execution_connect_by_ip",
		"default_download_policy",
		"content_view_publish_timeout",
		"http_proxy",
		"default_proxy",
		"snapshot_expiry",
	}

	detail.WriteString("Critical Settings:\n\n")
	detail.WriteString("[source, text]\n----\n")
	for _, setting := range criticalSettings {
		settingCmd := fmt.Sprintf("hammer settings list --search 'name ~ %s'", setting)
		settingOutput, _ := utils.RunCommand("bash", "-c", settingCmd)
		detail.WriteString(settingOutput)
		detail.WriteString("\n")
	}
	detail.WriteString("\n----\n\n")

	// Check for non-default settings
	nonDefaultCmd := "hammer settings list --search 'name !~ default' | grep -i 'yes' | grep -v '^--\\|^ID'"
	nonDefaultOutput, _ := utils.RunCommand("bash", "-c", nonDefaultCmd)

	detail.WriteString("Non-Default Settings:\n\n")
	if nonDefaultOutput == "" {
		detail.WriteString("No non-default settings found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(nonDefaultOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check email settings
	emailSettingsCmd := "hammer settings list --search 'name ~ mail or name ~ email or name ~ smtp'"
	emailSettingsOutput, _ := utils.RunCommand("bash", "-c", emailSettingsCmd)

	detail.WriteString("Email Configuration:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(emailSettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check proxy settings
	proxySettingsCmd := "hammer settings list --search 'name ~ proxy'"
	proxySettingsOutput, _ := utils.RunCommand("bash", "-c", proxySettingsCmd)

	detail.WriteString("Proxy Configuration:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(proxySettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check for problematic settings
	securityIssues := []string{}
	configurationIssues := []string{}

	// Check for security issues
	if strings.Contains(settingsOutput, "trusted_puppetmaster_hosts") &&
		!strings.Contains(settingsOutput, "trusted_puppetmaster_hosts |  |") {
		securityIssues = append(securityIssues, "trusted_puppetmaster_hosts is set - review for security")
	}

	if strings.Contains(settingsOutput, "websockets_encrypt | false") {
		securityIssues = append(securityIssues, "websockets_encrypt is set to false")
	}

	if strings.Contains(settingsOutput, "login_delegation_logout_url") &&
		!strings.Contains(settingsOutput, "login_delegation_logout_url |  |") {
		securityIssues = append(securityIssues, "login_delegation_logout_url is set - review configuration")
	}

	// Check for configuration issues
	if strings.Contains(settingsOutput, "default_download_policy | immediate") {
		configurationIssues = append(configurationIssues, "default_download_policy is set to immediate - may cause excessive storage use")
	}

	if !strings.Contains(emailSettingsOutput, "email_reply_address") ||
		strings.Contains(emailSettingsOutput, "email_reply_address |  |") {
		configurationIssues = append(configurationIssues, "email_reply_address is not configured")
	}

	// Create a security/configuration issues summary table
	if len(securityIssues) > 0 || len(configurationIssues) > 0 {
		detail.WriteString("{set:cellbgcolor!}\n")
		detail.WriteString("Settings Issues Summary:\n\n")
		detail.WriteString("[cols=\"1,2\", options=\"header\"]\n|===\n")
		detail.WriteString("|Issue Type|Details\n")

		if len(securityIssues) > 0 {
			detail.WriteString("|Security Issues|\n")
			for i, issue := range securityIssues {
				if i > 0 {
					detail.WriteString("\n")
				}
				detail.WriteString("* " + issue)
			}
			detail.WriteString("\n")
		}

		if len(configurationIssues) > 0 {
			detail.WriteString("|Configuration Issues|\n")
			for i, issue := range configurationIssues {
				if i > 0 {
					detail.WriteString("\n")
				}
				detail.WriteString("* " + issue)
			}
			detail.WriteString("\n")
		}
		detail.WriteString("|===\n\n")
	}

	// Evaluate results
	if len(securityIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d potential security issues in settings", len(securityIssues)),
			report.ResultKeyRecommended)
		for _, issue := range securityIssues {
			report.AddRecommendation(&check.Result, issue)
		}
		for _, issue := range configurationIssues {
			report.AddRecommendation(&check.Result, issue)
		}
	} else if len(configurationIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d configuration issues in settings", len(configurationIssues)),
			report.ResultKeyAdvisory)
		for _, issue := range configurationIssues {
			report.AddRecommendation(&check.Result, issue)
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Satellite settings appear to be properly configured",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/chap-red_hat_satellite-administering_red_hat_satellite-configuring_settings",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkInstallerConfig checks Satellite installer configuration
func checkInstallerConfig(r *report.AsciiDocReport) {
	checkID := "satellite-installer-config"
	checkName := "Installer Configuration"
	checkDesc := "Checks Satellite installer configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Installer Configuration Analysis:\n\n")

	// Check installer logs
	installerLogsCmd := "ls -la /var/log/foreman-installer/satellite.log*"
	installerLogsOutput, _ := utils.RunCommand("bash", "-c", installerLogsCmd)

	detail.WriteString("Installer Logs:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(installerLogsOutput)
	detail.WriteString("\n----\n\n")

	// Check recent installer run
	recentInstallerCmd := "tail -30 /var/log/foreman-installer/satellite.log"
	recentInstallerOutput, _ := utils.RunCommand("bash", "-c", recentInstallerCmd)

	detail.WriteString("Recent Installer Run:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(recentInstallerOutput)
	detail.WriteString("\n----\n\n")

	// Check installer answers file
	answersCmd := "cat /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null || cat /etc/foreman-installer/scenarios.d/satellite.yaml 2>/dev/null || echo 'Answers file not found'"
	answersOutput, _ := utils.RunCommand("bash", "-c", answersCmd)

	detail.WriteString("Installer Answers File:\n\n")
	if strings.Contains(answersOutput, "Answers file not found") {
		detail.WriteString("Answers file not found\n\n")
	} else {
		// Only show part of the answers file to avoid extremely long output
		answersLines := strings.Split(answersOutput, "\n")
		if len(answersLines) > 50 {
			detail.WriteString("[source, yaml]\n----\n")
			for i := 0; i < 50; i++ {
				detail.WriteString(answersLines[i] + "\n")
			}
			detail.WriteString("... (output truncated for brevity) ...\n")
			detail.WriteString("\n----\n\n")
		} else {
			detail.WriteString("[source, yaml]\n----\n")
			detail.WriteString(answersOutput)
			detail.WriteString("\n----\n\n")
		}
	}

	// Check custom-hiera.yaml if it exists
	hieraCmd := "cat /etc/foreman-installer/custom-hiera.yaml 2>/dev/null || echo 'Custom hiera file not found'"
	hieraOutput, _ := utils.RunCommand("bash", "-c", hieraCmd)

	detail.WriteString("Custom Hiera Configuration:\n\n")
	if strings.Contains(hieraOutput, "Custom hiera file not found") {
		detail.WriteString("Custom hiera file not found\n\n")
	} else {
		detail.WriteString("[source, yaml]\n----\n")
		detail.WriteString(hieraOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for ACTUAL errors in installer runs - only look for ERROR or FATAL log levels, not NOTICE
	installerErrorsCmd := "grep -E ' ERROR | FATAL ' /var/log/foreman-installer/satellite.log | tail -20"
	installerErrorsOutput, _ := utils.RunCommand("bash", "-c", installerErrorsCmd)

	detail.WriteString("Installer Errors:\n\n")
	if installerErrorsOutput == "" {
		detail.WriteString("No installer errors found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(installerErrorsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Determine if installer has issues - only consider actual errors, not NOTICE messages
	hasInstallerErrors := installerErrorsOutput != "" &&
		(strings.Contains(installerErrorsOutput, " ERROR ") || strings.Contains(installerErrorsOutput, " FATAL "))
	hasCustomConfig := !strings.Contains(hieraOutput, "Custom hiera file not found")
	lastInstallSuccessful := strings.Contains(recentInstallerOutput, "Success!") ||
		strings.Contains(recentInstallerOutput, "installer completed")

	// Create a summary table - fixing the table formatting
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Installer Configuration Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Status\n")
	detail.WriteString(fmt.Sprintf("|Last Installation Successful|%s\n", boolToYesNo(lastInstallSuccessful)))
	detail.WriteString(fmt.Sprintf("|Installer Errors Present|%s\n", boolToYesNo(hasInstallerErrors)))
	detail.WriteString(fmt.Sprintf("|Custom Hiera Configuration|%s\n", boolToYesNo(hasCustomConfig)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if hasInstallerErrors && !lastInstallSuccessful {
		check.Result = report.NewResult(report.StatusWarning,
			"Satellite installer errors detected with unsuccessful last run",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review installer errors in logs")
		report.AddRecommendation(&check.Result, "Run satellite-installer --help to see valid options")
		report.AddRecommendation(&check.Result, "Consider re-running installer with needed options")
	} else if hasInstallerErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Satellite installer errors detected but last run was successful",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review installer errors in logs")
		report.AddRecommendation(&check.Result, "Monitor for any issues related to the errors")
	} else if hasCustomConfig {
		check.Result = report.NewResult(report.StatusOK,
			"Custom Satellite configuration detected",
			report.ResultKeyNoChange)
		report.AddRecommendation(&check.Result, "Document custom configurations for future reference")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Standard Satellite installer configuration with no errors",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_satellite_server_from_a_connected_network/performing_additional_configuration",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1498553") // Satellite installer troubleshooting

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
