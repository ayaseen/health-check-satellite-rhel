// pkg/checks/satellite/plugin.go

package satellite

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunPluginChecks performs Satellite plugin checks
func RunPluginChecks(r *report.AsciiDocReport) {
	// Check for installed plugins
	checkInstalledPlugins(r)

	// Check plugin compatibility
	checkPluginCompatibility(r)

	// Check plugin functionality
	checkPluginFunctionality(r)
}

// checkInstalledPlugins checks which plugins are installed and their status
func checkInstalledPlugins(r *report.AsciiDocReport) {
	checkID := "satellite-plugins-installed"
	checkName := "Installed Plugins"
	checkDesc := "Checks which Satellite plugins are installed and their status."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all installed plugins
	pluginsCmd := "rpm -qa | grep -E 'foreman-.*plugin|katello-.*plugin|rubygem-foreman_.+'"
	pluginsOutput, err := utils.RunCommand("bash", "-c", pluginsCmd)

	var detail strings.Builder
	detail.WriteString("Installed Satellite Plugins:\n\n")

	if err != nil || pluginsOutput == "" {
		detail.WriteString("No plugins detected or error checking plugins\n")
		if err != nil {
			detail.WriteString("Error: " + err.Error() + "\n")
		}
		detail.WriteString("\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pluginsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for enabled plugins in Foreman configuration
	enabledPluginsCmd := "grep -r 'enable.*plugin' /etc/foreman/ 2>/dev/null"
	enabledPluginsOutput, _ := utils.RunCommand("bash", "-c", enabledPluginsCmd)

	detail.WriteString("Enabled Plugins Configuration:\n")
	if enabledPluginsOutput == "" {
		detail.WriteString("No enabled plugins configuration found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(enabledPluginsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for plugins in Satellite web UI
	aboutPluginsCmd := "foreman-rake about:plugins 2>/dev/null || echo 'Cannot get plugin information from foreman-rake'"
	aboutPluginsOutput, _ := utils.RunCommand("bash", "-c", aboutPluginsCmd)

	detail.WriteString("Foreman Plugin Information:\n")
	if !strings.Contains(aboutPluginsOutput, "Cannot get plugin information") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(aboutPluginsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("Could not retrieve plugin information from foreman-rake\n\n")
	}

	// Check for bundler plugins
	bundlerPluginsCmd := "grep -E 'gem.*foreman_|gem.*katello' /usr/share/gems/bundler/gems/*/Gemfile 2>/dev/null"
	bundlerPluginsOutput, _ := utils.RunCommand("bash", "-c", bundlerPluginsCmd)

	detail.WriteString("Bundler Gems for Plugins:\n")
	if bundlerPluginsOutput == "" {
		detail.WriteString("No bundler gems for plugins found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(bundlerPluginsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Count unique plugins
	pluginCount := 0
	officialPlugins := 0
	thirdPartyPlugins := 0

	if pluginsOutput != "" {
		lines := strings.Split(pluginsOutput, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			pluginCount++

			// Check if it's an official or third-party plugin
			if strings.Contains(line, "foreman_") || strings.Contains(line, "katello") {
				officialPlugins++
			} else {
				thirdPartyPlugins++
			}
		}
	}

	// Evaluate results
	if pluginCount == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"No Satellite plugins detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify if any plugins should be installed")
		report.AddRecommendation(&check.Result, "If plugins are installed, check why they were not detected")
	} else if thirdPartyPlugins > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d plugins installed (%d third-party)", pluginCount, thirdPartyPlugins),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review third-party plugins for compatibility")
		report.AddRecommendation(&check.Result, "Ensure third-party plugins are supported with your Satellite version")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d official plugins installed", officialPlugins),
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

// checkPluginCompatibility validates plugin versions are compatible with Satellite
func checkPluginCompatibility(r *report.AsciiDocReport) {
	checkID := "satellite-plugins-compatibility"
	checkName := "Plugin Compatibility"
	checkDesc := "Validates plugin versions are compatible with current Satellite version."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get Satellite version
	satelliteVersionCmd := "rpm -q satellite --queryformat '%{VERSION}' 2>/dev/null || rpm -q katello --queryformat '%{VERSION}' 2>/dev/null"
	satelliteVersionOutput, _ := utils.RunCommand("bash", "-c", satelliteVersionCmd)
	satelliteVersion := strings.TrimSpace(satelliteVersionOutput)

	var detail strings.Builder
	detail.WriteString("Plugin Compatibility Analysis:\n\n")
	detail.WriteString(fmt.Sprintf("Satellite Version: %s\n\n", satelliteVersion))

	// Get plugin versions
	pluginVersionsCmd := "rpm -qa --queryformat '%{NAME} %{VERSION}\\n' | grep -E 'foreman-.*plugin|katello-.*plugin|rubygem-foreman_.+'"
	pluginVersionsOutput, _ := utils.RunCommand("bash", "-c", pluginVersionsCmd)

	detail.WriteString("Plugin Versions:\n")
	if pluginVersionsOutput == "" {
		detail.WriteString("No plugin version information found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pluginVersionsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for plugin errors in logs
	pluginErrorsCmd := "grep -E 'plugin.*error|plugin.*fail|error.*plugin' /var/log/foreman/production.log /var/log/messages 2>/dev/null | tail -20"
	pluginErrorsOutput, _ := utils.RunCommand("bash", "-c", pluginErrorsCmd)

	detail.WriteString("Plugin Errors in Logs:\n")
	if pluginErrorsOutput == "" {
		detail.WriteString("No plugin errors found in logs\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pluginErrorsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Look for dependency issues
	dependencyCmd := "foreman-rake plugin:analyze_dependencies 2>/dev/null || echo 'Cannot check plugin dependencies'"
	dependencyOutput, _ := utils.RunCommand("bash", "-c", dependencyCmd)

	detail.WriteString("Plugin Dependency Analysis:\n")
	if !strings.Contains(dependencyOutput, "Cannot check plugin dependencies") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(dependencyOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("Could not analyze plugin dependencies\n\n")
	}

	// Determine if there are issues
	hasPluginErrors := pluginErrorsOutput != ""
	hasDependencyIssues := strings.Contains(dependencyOutput, "conflict") ||
		strings.Contains(dependencyOutput, "issue") ||
		strings.Contains(dependencyOutput, "error")

	// Evaluate results
	if hasPluginErrors && hasDependencyIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Plugin errors and dependency issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review plugin errors in logs")
		report.AddRecommendation(&check.Result, "Check plugin dependencies and compatibility")
		report.AddRecommendation(&check.Result, "Consider updating plugins to compatible versions")
	} else if hasPluginErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Plugin errors detected in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review plugin errors in logs")
		report.AddRecommendation(&check.Result, "Consider updating problematic plugins")
	} else if hasDependencyIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Plugin dependency issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Resolve plugin dependency conflicts")
		report.AddRecommendation(&check.Result, "Check plugin compatibility with current Satellite version")
	} else if pluginVersionsOutput == "" {
		check.Result = report.NewResult(report.StatusWarning,
			"No plugin information found to check compatibility",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify if plugins are installed")
		report.AddRecommendation(&check.Result, "Check if all plugins are properly registered")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No plugin compatibility issues detected",
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

// checkPluginFunctionality checks if installed plugins are functioning properly
func checkPluginFunctionality(r *report.AsciiDocReport) {
	checkID := "satellite-plugins-functionality"
	checkName := "Plugin Functionality"
	checkDesc := "Checks if installed plugins are functioning properly."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Plugin Functionality Analysis:\n\n")

	// Check for plugin routes/endpoints
	routesCmd := "foreman-rake routes | grep -E 'plugin|/api/v2/' | head -20"
	routesOutput, _ := utils.RunCommand("bash", "-c", routesCmd)

	detail.WriteString("Plugin Routes (sample):\n")
	if routesOutput == "" {
		detail.WriteString("No plugin routes found or could not check routes\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(routesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check plugin settings
	settingsCmd := "hammer settings list --search 'name ~ plugin'"
	settingsOutput, _ := utils.RunCommand("bash", "-c", settingsCmd)

	detail.WriteString("Plugin Settings:\n")
	if settingsOutput == "" {
		detail.WriteString("No plugin settings found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(settingsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for recent plugin errors
	recentErrorsCmd := "grep -E 'plugin.*error|plugin.*exception' /var/log/foreman/production.log 2>/dev/null | tail -20"
	recentErrorsOutput, _ := utils.RunCommand("bash", "-c", recentErrorsCmd)

	detail.WriteString("Recent Plugin Errors:\n")
	if recentErrorsOutput == "" {
		detail.WriteString("No recent plugin errors found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(recentErrorsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Get list of installed plugins
	pluginListCmd := "rpm -qa | grep -E 'foreman-.*plugin|katello-.*plugin|rubygem-foreman_.+'"
	pluginListOutput, _ := utils.RunCommand("bash", "-c", pluginListCmd)

	// Check health for each major plugin type
	detail.WriteString("Plugin Health Checks:\n")

	// Only check for major plugins that are installed
	if strings.Contains(pluginListOutput, "remote_execution") {
		rexHealthCmd := "hammer job-invocation list --per-page 1"
		rexHealthOutput, _ := utils.RunCommand("bash", "-c", rexHealthCmd)
		detail.WriteString("Remote Execution Plugin: ")
		if strings.Contains(rexHealthOutput, "Error") {
			detail.WriteString("Issues detected\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(rexHealthOutput)
			detail.WriteString("\n----\n")
		} else {
			detail.WriteString("Functional\n")
		}
	}

	if strings.Contains(pluginListOutput, "discovery") {
		discoveryHealthCmd := "hammer settings list --search 'name ~ discovery'"
		discoveryHealthOutput, _ := utils.RunCommand("bash", "-c", discoveryHealthCmd)
		detail.WriteString("Discovery Plugin: ")
		if strings.Contains(discoveryHealthOutput, "Error") {
			detail.WriteString("Issues detected\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(discoveryHealthOutput)
			detail.WriteString("\n----\n")
		} else {
			detail.WriteString("Functional\n")
		}
	}

	if strings.Contains(pluginListOutput, "ansible") {
		ansibleHealthCmd := "hammer settings list --search 'name ~ ansible'"
		ansibleHealthOutput, _ := utils.RunCommand("bash", "-c", ansibleHealthCmd)
		detail.WriteString("Ansible Plugin: ")
		if strings.Contains(ansibleHealthOutput, "Error") {
			detail.WriteString("Issues detected\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(ansibleHealthOutput)
			detail.WriteString("\n----\n")
		} else {
			detail.WriteString("Functional\n")
		}
	}

	// Determine if there are issues
	hasErrors := recentErrorsOutput != ""
	noPlugins := pluginListOutput == ""

	// Evaluate results
	if hasErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Plugin functionality issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review plugin errors in logs")
		report.AddRecommendation(&check.Result, "Check affected plugin functionality in Satellite web UI")
		report.AddRecommendation(&check.Result, "Consider restarting Satellite services: satellite-maintain service restart")
	} else if noPlugins {
		check.Result = report.NewResult(report.StatusWarning,
			"No plugins detected to check functionality",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify if plugins should be installed")
	} else if routesOutput == "" {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not verify plugin functionality completely",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Manually verify plugin functionality in Satellite web UI")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Installed plugins appear to be functioning properly",
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
