// pkg/checks/rhel/connectivity.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunConnectivityChecks performs connectivity related checks
func RunConnectivityChecks(r *report.AsciiDocReport) {
	// Validate access to dependent services (DBs, APIs)
	checkDependentServices(r)

	// Confirm DNS records and reverse lookups
	checkDNSRecords(r)

	// Check network latency to key systems
	checkNetworkLatency(r)
}

// checkDependentServices validates access to dependent services (DBs, APIs)
func checkDependentServices(r *report.AsciiDocReport) {
	checkID := "connectivity-services"
	checkName := "Dependent Services"
	checkDesc := "Validates access to dependent services (DBs, APIs)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Try to detect dependent services
	// Check common services in netstat - Expanded to capture both IPv4 and IPv6
	netstatCmd := "ss -tuln | grep -E ':(80|443|3306|5432|8080|8443|9200|27017|6379)'"
	netstatOutput, _ := utils.RunCommand("bash", "-c", netstatCmd)

	// Parse listening services to get actual IPs and ports
	var localServices []struct {
		ip   string
		port string
		desc string
	}

	if netstatOutput != "" {
		for _, line := range strings.Split(netstatOutput, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}

			// Extract the IP:PORT pattern from the netstat output
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				addrParts := strings.Split(parts[4], ":")
				if len(addrParts) >= 2 {
					ip := strings.Join(addrParts[:len(addrParts)-1], ":")
					port := addrParts[len(addrParts)-1]

					// Clean up IPv6 address formatting if present
					ip = strings.TrimPrefix(ip, "[")
					ip = strings.TrimSuffix(ip, "]")

					// Skip if the IP is a wildcard address
					if ip == "*" || ip == "0.0.0.0" || ip == "::" {
						continue
					}

					// Determine service type based on port
					serviceDesc := "Unknown Service"
					switch port {
					case "80", "8080":
						serviceDesc = "HTTP Service"
					case "443", "8443":
						serviceDesc = "HTTPS Service"
					case "3306":
						serviceDesc = "MySQL/MariaDB"
					case "5432":
						serviceDesc = "PostgreSQL"
					case "9200":
						serviceDesc = "Elasticsearch"
					case "27017":
						serviceDesc = "MongoDB"
					case "6379":
						serviceDesc = "Redis"
					}

					localServices = append(localServices, struct {
						ip   string
						port string
						desc string
					}{ip, port, serviceDesc})
				}
			}
		}
	}

	// Check for configured database connections
	// Look in common configuration files
	dbConfigCmd := "grep -r -l -E '(database|db_host|connection|jdbc|mysql|postgresql)' /etc/[a-z]* 2>/dev/null | head -5"
	dbConfigOutput, _ := utils.RunCommand("bash", "-c", dbConfigCmd)

	// If we found config files, try to extract hostnames and IPs more carefully
	var dbHosts []struct {
		host string
		port string
		desc string
	}

	if dbConfigOutput != "" {
		// Extract hostnames with domain
		hostsCmd := "grep -h -E '(host|hostname|server)\\s*=\\s*[\"'']?[a-zA-Z0-9.-]+\\.[a-zA-Z0-9.-]+[\"'']?' " +
			dbConfigOutput + " 2>/dev/null | grep -oE '[a-zA-Z0-9.-]+\\.[a-zA-Z0-9.-]+'"
		hostsOutput, _ := utils.RunCommand("bash", "-c", hostsCmd)

		// Also try to extract IP addresses
		ipsCmd := "grep -h -E '(host|hostname|server|address)\\s*=\\s*[\"'']?[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}[\"'']?' " +
			dbConfigOutput + " 2>/dev/null | grep -oE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'"
		ipsOutput, _ := utils.RunCommand("bash", "-c", ipsCmd)

		// Process hostnames
		if hostsOutput != "" {
			for _, host := range strings.Split(hostsOutput, "\n") {
				host = strings.TrimSpace(host)
				if host == "" || host == "localhost" || host == "127.0.0.1" {
					continue
				}

				// Try to determine port and service type
				port := "5432" // Default to PostgreSQL
				desc := "Database"

				if strings.Contains(host, "mysql") || strings.Contains(host, "mariadb") {
					port = "3306"
					desc = "MySQL/MariaDB"
				} else if strings.Contains(host, "mongo") {
					port = "27017"
					desc = "MongoDB"
				} else if strings.Contains(host, "redis") {
					port = "6379"
					desc = "Redis"
				} else if strings.Contains(host, "elastic") {
					port = "9200"
					desc = "Elasticsearch"
				}

				dbHosts = append(dbHosts, struct {
					host string
					port string
					desc string
				}{host, port, desc})
			}
		}

		// Process IP addresses
		if ipsOutput != "" {
			for _, ip := range strings.Split(ipsOutput, "\n") {
				ip = strings.TrimSpace(ip)
				if ip == "" || ip == "127.0.0.1" || ip == "0.0.0.0" {
					continue
				}

				// Default port is PostgreSQL
				dbHosts = append(dbHosts, struct {
					host string
					port string
					desc string
				}{ip, "5432", "Database (IP)"})
			}
		}
	}

	var detail strings.Builder
	detail.WriteString("Local Services:\n")
	detail.WriteString("[source, bash]\n----\n")
	if netstatOutput != "" {
		detail.WriteString(netstatOutput)
	} else {
		detail.WriteString("No common service ports detected\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Database Configurations Found:\n")
	detail.WriteString("[source, bash]\n----\n")
	if dbConfigOutput != "" {
		detail.WriteString(dbConfigOutput)
	} else {
		detail.WriteString("No database configurations detected\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Connectivity Tests:\n")
	detail.WriteString("[source, bash]\n----\n")

	// Test connectivity to detected services
	var unreachableServices []string
	testCount := 0

	// Test local listening services first
	for _, service := range localServices {
		testCount++
		ncCmd := fmt.Sprintf("timeout 2 nc -zv %s %s 2>&1 || echo 'Connection failed'", service.ip, service.port)
		ncOutput, _ := utils.RunCommand("bash", "-c", ncCmd)

		detail.WriteString(fmt.Sprintf("Local %s (%s:%s): ", service.desc, service.ip, service.port))
		if strings.Contains(ncOutput, "succeeded") {
			detail.WriteString("Successful\n")
		} else {
			detail.WriteString("Failed\n")
			unreachableServices = append(unreachableServices,
				fmt.Sprintf("Local %s (%s:%s)", service.desc, service.ip, service.port))
		}
	}

	// Test DB hosts found in config files
	for _, dbHost := range dbHosts {
		testCount++
		ncCmd := fmt.Sprintf("timeout 2 nc -zv %s %s 2>&1 || echo 'Connection failed'", dbHost.host, dbHost.port)
		ncOutput, _ := utils.RunCommand("bash", "-c", ncCmd)

		detail.WriteString(fmt.Sprintf("%s (%s:%s): ", dbHost.desc, dbHost.host, dbHost.port))
		if strings.Contains(ncOutput, "succeeded") {
			detail.WriteString("Successful\n")
		} else {
			detail.WriteString("Failed\n")
			unreachableServices = append(unreachableServices,
				fmt.Sprintf("%s (%s:%s)", dbHost.desc, dbHost.host, dbHost.port))
		}
	}
	detail.WriteString("\n----\n")

	// Check if system appears to be in a disconnected environment
	// Avoid external tests completely so we don't generate errors in disconnected environments
	isDisconnectedEnv := false
	wanCheckCmd := "ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 || echo 'disconnected'"
	wanCheckOutput, _ := utils.RunCommand("bash", "-c", wanCheckCmd)
	if strings.Contains(wanCheckOutput, "disconnected") {
		isDisconnectedEnv = true
		detail.WriteString("\nNote: System appears to be in a disconnected environment.\n")
	}

	// Evaluate connectivity - Always report as advisory level
	if testCount == 0 {
		check.Result = report.NewResult(report.StatusInfo,
			"No dependent services detected to test connectivity",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "If this system connects to dependent services, they should be tested manually")
	} else if len(unreachableServices) > 0 {
		check.Result = report.NewResult(report.StatusInfo,
			fmt.Sprintf("%d of %d local services may be unreachable", len(unreachableServices), testCount),
			report.ResultKeyAdvisory)

		for _, service := range unreachableServices {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Verify connectivity to %s", service))
		}

		if isDisconnectedEnv {
			report.AddRecommendation(&check.Result, "System appears to be in a disconnected environment - some connection failures are expected")
		}

		// Add RHEL documentation reference as a direct link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/configuring-the-order-of-dns-servers_configuring-and-managing-networking", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("All %d detected local services are reachable", testCount),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkDNSRecords confirms DNS records and reverse lookups
func checkDNSRecords(r *report.AsciiDocReport) {
	checkID := "connectivity-dns"
	checkName := "DNS Records"
	checkDesc := "Confirms DNS records and reverse lookups."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get system hostname
	hostnameCmd := "hostname -f"
	hostnameOutput, _ := utils.RunCommand("bash", "-c", hostnameCmd)
	hostname := strings.TrimSpace(hostnameOutput)

	// Get IP addresses
	ipAddressCmd := "hostname -I"
	ipAddressOutput, _ := utils.RunCommand("bash", "-c", ipAddressCmd)
	ipAddresses := strings.Fields(ipAddressOutput)

	// Check forward DNS resolution
	var forwardLookupResult string
	if hostname != "" {
		forwardCmd := fmt.Sprintf("getent hosts %s || echo 'No forward DNS record found'", hostname)
		forwardLookupResult, _ = utils.RunCommand("bash", "-c", forwardCmd)
	} else {
		forwardLookupResult = "No hostname available to lookup"
	}

	// Check reverse DNS for each IP
	var detail strings.Builder
	detail.WriteString("Hostname Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	detail.WriteString(fmt.Sprintf("IP Addresses: %s\n", strings.Join(ipAddresses, ", ")))
	detail.WriteString("\n----\n\n")

	detail.WriteString("Forward DNS Lookup:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(forwardLookupResult)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Reverse DNS Lookups:\n")
	detail.WriteString("[source, bash]\n----\n")

	var dnsIssues []string
	hasReverseLookup := false

	// Forward lookup issue check
	forwardLookupSuccessful := !strings.Contains(forwardLookupResult, "No forward DNS record found") && forwardLookupResult != "No hostname available to lookup"

	if !forwardLookupSuccessful {
		dnsIssues = append(dnsIssues, fmt.Sprintf("Forward DNS lookup for %s failed", hostname))
	}

	// Check reverse lookups
	for _, ip := range ipAddresses {
		if strings.TrimSpace(ip) == "" || ip == "127.0.0.1" || ip == "::1" {
			continue
		}

		reverseCmdBash := fmt.Sprintf("getent hosts %s || echo 'No reverse DNS record found'", ip)
		reverseLookupResult, _ := utils.RunCommand("bash", "-c", reverseCmdBash)

		detail.WriteString(fmt.Sprintf("IP %s: ", ip))
		if strings.Contains(reverseLookupResult, "No reverse DNS record found") {
			detail.WriteString("Failed\n")
			dnsIssues = append(dnsIssues, fmt.Sprintf("Reverse DNS lookup for IP %s failed", ip))
		} else {
			detail.WriteString("Successful\n")
			detail.WriteString(reverseLookupResult + "\n")
			hasReverseLookup = true
		}
	}
	detail.WriteString("\n----\n\n")

	// Check resolv.conf
	resolvConfCmd := "cat /etc/resolv.conf | grep -v '^#'"
	resolvConfOutput, _ := utils.RunCommand("bash", "-c", resolvConfCmd)

	detail.WriteString("DNS Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(resolvConfOutput)
	detail.WriteString("\n----\n")

	// Count nameservers
	nameserverCount := 0
	for _, line := range strings.Split(resolvConfOutput, "\n") {
		if strings.HasPrefix(line, "nameserver") {
			nameserverCount++
		}
	}

	if nameserverCount < 2 {
		dnsIssues = append(dnsIssues, fmt.Sprintf("Only %d nameserver(s) configured", nameserverCount))
	}

	// Evaluate DNS configuration
	if len(dnsIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d DNS resolution issues", len(dnsIssues)),
			report.ResultKeyRecommended)

		for _, issue := range dnsIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !forwardLookupSuccessful || !hasReverseLookup {
			report.AddRecommendation(&check.Result, "Configure proper DNS records for this system's hostname and IP addresses")
		}

		if nameserverCount < 2 {
			report.AddRecommendation(&check.Result, "Configure at least two nameservers in /etc/resolv.conf for redundancy")
		}

		// Add RHEL documentation reference as direct link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/using-networkmanager-with-network-scripts_configuring-and-managing-networking", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"DNS records and lookups are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkNetworkLatency checks network latency to key systems
func checkNetworkLatency(r *report.AsciiDocReport) {
	checkID := "connectivity-latency"
	checkName := "Network Latency"
	checkDesc := "Checks network latency to key systems."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get default gateway
	gatewayCmd := "ip route | grep default | awk '{print $3}'"
	gatewayOutput, _ := utils.RunCommand("bash", "-c", gatewayCmd)
	gateway := strings.TrimSpace(gatewayOutput)

	// Define key systems to check
	keySystems := []struct {
		name string
		host string
	}{
		{"Default Gateway", gateway},
		{"Google DNS", "8.8.8.8"},
		{"Cloudflare DNS", "1.1.1.1"},
		{"Red Hat", "access.redhat.com"},
	}

	var detail strings.Builder
	detail.WriteString("Network Latency Tests:\n")
	detail.WriteString("[source, bash]\n----\n")

	// Run ping tests to measure latency
	var highLatencySystems []string
	testCount := 0

	for _, system := range keySystems {
		if system.host == "" {
			continue
		}

		testCount++
		// Use -c 3 for 3 pings with timeout of 1 second per ping
		pingCmd := fmt.Sprintf("ping -c 3 -W 1 %s 2>&1 || echo 'Ping failed'", system.host)
		pingOutput, _ := utils.RunCommand("bash", "-c", pingCmd)

		// Get average latency
		avgLatency := "N/A"
		for _, line := range strings.Split(pingOutput, "\n") {
			if strings.Contains(line, "min/avg/max") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					latencyParts := strings.Split(parts[1], "/")
					if len(latencyParts) > 1 {
						avgLatency = strings.TrimSpace(latencyParts[1])
					}
				}
			}
		}

		detail.WriteString(fmt.Sprintf("%s (%s): ", system.name, system.host))
		if strings.Contains(pingOutput, "Ping failed") {
			detail.WriteString("Failed - host unreachable\n")
			highLatencySystems = append(highLatencySystems, fmt.Sprintf("%s (%s) is unreachable", system.name, system.host))
		} else if avgLatency != "N/A" {
			detail.WriteString(fmt.Sprintf("Average latency: %s ms\n", avgLatency))

			// Parse latency as float
			var latencyValue float64
			fmt.Sscanf(avgLatency, "%f", &latencyValue)

			// Check for high latency (>100ms)
			if latencyValue > 100 {
				highLatencySystems = append(highLatencySystems, fmt.Sprintf("%s (%s) has high latency: %s ms", system.name, system.host, avgLatency))
			}
		} else {
			detail.WriteString("Completed but couldn't determine latency\n")
		}

		// Add ping output for detailed information
		detail.WriteString("  Ping Output:\n")
		for _, line := range strings.Split(pingOutput, "\n") {
			if strings.TrimSpace(line) != "" {
				detail.WriteString("  " + line + "\n")
			}
		}
		detail.WriteString("\n")
	}
	detail.WriteString("\n----\n\n")

	// Use tracepath (available by default) instead of traceroute
	detail.WriteString("Network Path to access.redhat.com:\n")
	detail.WriteString("[source, bash]\n----\n")

	// Try tracepath first (available by default in iputils package)
	tracepathCmd := "tracepath -n access.redhat.com 2>&1 || echo 'Tracepath not available'"
	tracepathOutput, _ := utils.RunCommand("bash", "-c", tracepathCmd)

	// If tracepath isn't available or fails, try ping with record route
	if strings.Contains(tracepathOutput, "not available") || strings.Contains(tracepathOutput, "command not found") {
		detail.WriteString("Tracepath not available, trying ping record-route:\n")
		pingRouteCmd := "ping -R -c 4 access.redhat.com 2>&1 || echo 'Ping record route failed'"
		pingRouteOutput, _ := utils.RunCommand("bash", "-c", pingRouteCmd)
		detail.WriteString(pingRouteOutput)
	} else {
		detail.WriteString(tracepathOutput)
	}

	detail.WriteString("\n----\n")

	// Check for high latency in path (look for patterns in both tracepath and ping -R outputs)
	highLatencyInPath := false

	// Parse tracepath output (numbers followed by ms)
	for _, line := range strings.Split(tracepathOutput, "\n") {
		if strings.Contains(line, "ms") {
			latencyFields := strings.Fields(line)
			for _, field := range latencyFields {
				var latencyValue float64
				// Try to extract just the numeric part before "ms"
				if strings.HasSuffix(field, "ms") {
					numPart := strings.TrimSuffix(field, "ms")
					if n, err := fmt.Sscanf(numPart, "%f", &latencyValue); n == 1 && err == nil {
						if latencyValue > 200 {
							highLatencyInPath = true
							break
						}
					}
				}
			}
		}
	}

	if highLatencyInPath {
		highLatencySystems = append(highLatencySystems, "High latency detected in network path")
	}

	// Evaluate network latency
	if testCount == 0 {
		check.Result = report.NewResult(report.StatusInfo,
			"No hosts available to test network latency",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Configure proper networking to enable latency testing")
	} else if len(highLatencySystems) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d latency or connectivity issues", len(highLatencySystems)),
			report.ResultKeyRecommended)

		for _, issue := range highLatencySystems {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Investigate network path and routing for latency issues")
		report.AddRecommendation(&check.Result, "Check for network congestion or misconfigured network equipment")

		// Add RHEL documentation reference as direct link
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/managing-network-performance-with-ethtool_monitoring-and-managing-system-status-and-performance", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Network latency to key systems is within acceptable ranges",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
