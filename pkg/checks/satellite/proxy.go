// pkg/checks/satellite/proxy.go

package satellite

import (
	"fmt"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"strings"
)

// RunProxyChecks performs Satellite HTTP proxy checks
func RunProxyChecks(r *report.AsciiDocReport) {
	// Check HTTP proxy configuration
	checkHTTPProxyConfig(r)

	// Check proxy connectivity
	checkProxyConnectivity(r)
}

// checkHTTPProxyConfig checks HTTP proxy configuration
func checkHTTPProxyConfig(r *report.AsciiDocReport) {
	checkID := "satellite-http-proxy"
	checkName := "HTTP Proxy Configuration"
	checkDesc := "Checks Satellite's HTTP proxy configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("HTTP Proxy Configuration Analysis:\n\n")

	// Check global proxy settings
	globalProxyCmd := "hammer settings list --search 'name ~ http_proxy'"
	globalProxyOutput, _ := utils.RunCommand("bash", "-c", globalProxyCmd)

	detail.WriteString("Global HTTP Proxy Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(globalProxyOutput)
	detail.WriteString("\n----\n\n")

	// Check proxy objects
	proxyObjectsCmd := "hammer http-proxy list"
	proxyObjectsOutput, _ := utils.RunCommand("bash", "-c", proxyObjectsCmd)

	detail.WriteString("HTTP Proxy Objects:\n")
	if !strings.Contains(proxyObjectsOutput, "No http proxies found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(proxyObjectsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No HTTP proxy objects found\n\n")
	}

	// Check product proxy associations
	productProxyCmd := "hammer product list --fields id,name,http_proxy_id"
	productProxyOutput, _ := utils.RunCommand("bash", "-c", productProxyCmd)

	detail.WriteString("Product Proxy Associations:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(productProxyOutput)
	detail.WriteString("\n----\n\n")

	// Check for proxy configuration in yum repos
	yumProxyCmd := "grep -r 'proxy' /etc/yum.repos.d/ 2>/dev/null"
	yumProxyOutput, _ := utils.RunCommand("bash", "-c", yumProxyCmd)

	detail.WriteString("Proxy Configuration in YUM Repos:\n")
	if yumProxyOutput == "" {
		detail.WriteString("No proxy configuration found in YUM repos\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(yumProxyOutput)
		detail.WriteString("\n----\n")
	}

	// Determine proxy configuration status
	hasGlobalProxy := strings.Contains(globalProxyOutput, "http_proxy") &&
		!strings.Contains(globalProxyOutput, "http_proxy |  |")
	hasProxyObjects := !strings.Contains(proxyObjectsOutput, "No http proxies found")

	// Evaluate results
	if !hasGlobalProxy && !hasProxyObjects {
		check.Result = report.NewResult(report.StatusWarning,
			"No HTTP proxy configuration found",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Configure HTTP proxy if internet access is via proxy")
		report.AddRecommendation(&check.Result, "If direct internet access is available, this can be ignored")
	} else if hasGlobalProxy && !hasProxyObjects {
		check.Result = report.NewResult(report.StatusWarning,
			"Global HTTP proxy configured but no proxy objects defined",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider creating HTTP proxy objects for more fine-grained control")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"HTTP proxy configuration appears proper",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkProxyConnectivity checks proxy connectivity
func checkProxyConnectivity(r *report.AsciiDocReport) {
	checkID := "satellite-proxy-connectivity"
	checkName := "Proxy Connectivity"
	checkDesc := "Checks connectivity through configured HTTP proxies."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Proxy Connectivity Analysis:\n\n")

	// Get proxy settings
	proxiesCmd := "hammer http-proxy list --fields id,name,url"
	proxiesOutput, _ := utils.RunCommand("bash", "-c", proxiesCmd)

	if strings.Contains(proxiesOutput, "No http proxies found") {
		detail.WriteString("No HTTP proxies configured to test\n")

		check.Result = report.NewResult(report.StatusWarning,
			"No HTTP proxies configured to test connectivity",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "If proxy is required for internet access, configure HTTP proxy")

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("Configured HTTP Proxies:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(proxiesOutput)
	detail.WriteString("\n----\n\n")

	// Extract proxy URLs for testing
	proxyURLs := []string{}
	lines := strings.Split(proxiesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
			// Extract URL from line with format like: "| 1 | Main Proxy | https://proxy.example.com:8080 |"
			fields := strings.Split(line, "|")
			for _, field := range fields {
				if strings.Contains(field, "http") {
					proxyURLs = append(proxyURLs, strings.TrimSpace(field))
				}
			}
		}
	}

	// Test connectivity for each proxy
	detail.WriteString("Proxy Connectivity Tests:\n")

	proxySuccessCount := 0
	proxyFailCount := 0

	for _, proxyURL := range proxyURLs {
		// Try to parse the proxy URL to extract host and port
		proxyParts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(proxyURL, "http://"), "https://"), ":")
		proxyHost := proxyParts[0]
		proxyPort := "3128" // Default proxy port
		if len(proxyParts) > 1 {
			proxyPort = proxyParts[1]
		}

		// Test TCP connectivity to proxy
		connectCmd := fmt.Sprintf("timeout 5 nc -zv %s %s 2>&1", proxyHost, proxyPort)
		connectOutput, err := utils.RunCommand("bash", "-c", connectCmd)

		detail.WriteString(fmt.Sprintf("Testing %s: ", proxyURL))
		if err == nil && (strings.Contains(connectOutput, "succeeded") || strings.Contains(connectOutput, "open")) {
			detail.WriteString("SUCCESS\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(connectOutput)
			detail.WriteString("\n----\n")
			proxySuccessCount++
		} else {
			detail.WriteString("FAILED\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(connectOutput)
			detail.WriteString("\n----\n")
			proxyFailCount++
		}
	}
	detail.WriteString("\n")

	// Try a basic connectivity test through proxy
	if len(proxyURLs) > 0 {
		testURL := "https://access.redhat.com"
		testCmd := fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' --connect-timeout 10 -x %s %s", proxyURLs[0], testURL)
		testOutput, _ := utils.RunCommand("bash", "-c", testCmd)

		detail.WriteString(fmt.Sprintf("Testing connection to %s through first proxy: ", testURL))
		if testOutput == "200" || testOutput == "301" || testOutput == "302" {
			detail.WriteString(fmt.Sprintf("SUCCESS (HTTP %s)\n", testOutput))
		} else {
			detail.WriteString(fmt.Sprintf("FAILED (HTTP %s)\n", testOutput))
		}
	}

	// Evaluate results
	if proxyFailCount > 0 && proxySuccessCount == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("All %d configured HTTP proxies failed connectivity tests", proxyFailCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify proxy server connectivity and configuration")
		report.AddRecommendation(&check.Result, "Check network firewall rules between Satellite and proxy")
	} else if proxyFailCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d of %d HTTP proxies failed connectivity tests",
				proxyFailCount, proxyFailCount+proxySuccessCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify failing proxy server connectivity")
	} else if proxySuccessCount > 0 {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("All %d HTTP proxies are accessible", proxySuccessCount),
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not test HTTP proxy connectivity",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Manually verify HTTP proxy connectivity")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// pkg/checks/satellite/legacy.go

// RunLegacyChecks performs checks on deprecated or legacy Satellite features
func RunLegacyChecks(r *report.AsciiDocReport) {
	// Check for legacy features and configuration
	checkLegacyFeatures(r)
}

// checkLegacyFeatures checks for deprecated or legacy features and configuration
func checkLegacyFeatures(r *report.AsciiDocReport) {
	checkID := "satellite-legacy-features"
	checkName := "Legacy Features"
	checkDesc := "Checks for deprecated or legacy features and configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Legacy Features Analysis:\n\n")

	// Check for deprecated API usage
	legacyAPICmd := "grep -r 'api/v1\\|apiv1' /var/log/httpd/access_log 2>/dev/null | head -10"
	legacyAPIOutput, _ := utils.RunCommand("bash", "-c", legacyAPICmd)

	detail.WriteString("Deprecated API Usage:\n")
	if legacyAPIOutput == "" {
		detail.WriteString("No deprecated API usage found\n\n")
	} else {
		detail.WriteString("Found deprecated API v1 usage:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(legacyAPIOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for legacy puppet integration
	puppetCmd := "rpm -qa | grep -E 'puppet|foreman_puppet'"
	puppetOutput, _ := utils.RunCommand("bash", "-c", puppetCmd)

	detail.WriteString("Legacy Puppet Integration:\n")
	if puppetOutput == "" {
		detail.WriteString("No Puppet integration found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(puppetOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for legacy Katello agent usage
	katelloAgentCmd := "grep -r 'katello-agent' /var/log/httpd /var/log/foreman 2>/dev/null | head -10"
	katelloAgentOutput, _ := utils.RunCommand("bash", "-c", katelloAgentCmd)

	detail.WriteString("Legacy Katello Agent Usage:\n")
	if katelloAgentOutput == "" {
		detail.WriteString("No Katello agent usage found\n\n")
	} else {
		detail.WriteString("Found Katello agent usage (deprecated):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(katelloAgentOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for legacy Pulp v2 usage
	pulpV2Cmd := "rpm -qa | grep -E 'pulp-.*-2|pulp-2'"
	pulpV2Output, _ := utils.RunCommand("bash", "-c", pulpV2Cmd)

	detail.WriteString("Legacy Pulp v2 Usage:\n")
	if pulpV2Output == "" {
		detail.WriteString("No Pulp v2 packages found\n")
	} else {
		detail.WriteString("Found Pulp v2 packages (legacy):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pulpV2Output)
		detail.WriteString("\n----\n")
	}

	// Determine legacy feature status
	hasLegacyAPI := legacyAPIOutput != ""
	hasPuppet := puppetOutput != ""
	hasKatelloAgent := katelloAgentOutput != ""
	hasPulpV2 := pulpV2Output != ""

	legacyFeatureCount := 0
	if hasLegacyAPI {
		legacyFeatureCount++
	}
	if hasPuppet {
		legacyFeatureCount++
	}
	if hasKatelloAgent {
		legacyFeatureCount++
	}
	if hasPulpV2 {
		legacyFeatureCount++
	}

	// Evaluate results
	if legacyFeatureCount > 1 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d legacy/deprecated features detected", legacyFeatureCount),
			report.ResultKeyRecommended)

		if hasLegacyAPI {
			report.AddRecommendation(&check.Result, "Update scripts or applications to use current API versions (v2)")
		}
		if hasPuppet {
			report.AddRecommendation(&check.Result, "Consider migrating from Puppet to Ansible for configuration management")
		}
		if hasKatelloAgent {
			report.AddRecommendation(&check.Result, "Migrate from Katello agent to Remote Execution or Ansible")
		}
		if hasPulpV2 {
			report.AddRecommendation(&check.Result, "Upgrade to Pulp v3 for improved content management")
		}
	} else if legacyFeatureCount == 1 {
		check.Result = report.NewResult(report.StatusWarning,
			"One legacy/deprecated feature detected",
			report.ResultKeyAdvisory)

		if hasLegacyAPI {
			report.AddRecommendation(&check.Result, "Update scripts or applications to use current API versions (v2)")
		}
		if hasPuppet {
			report.AddRecommendation(&check.Result, "Consider migrating from Puppet to Ansible for configuration management")
		}
		if hasKatelloAgent {
			report.AddRecommendation(&check.Result, "Migrate from Katello agent to Remote Execution or Ansible")
		}
		if hasPulpV2 {
			report.AddRecommendation(&check.Result, "Upgrade to Pulp v3 for improved content management")
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No legacy/deprecated features detected",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/release_notes",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
