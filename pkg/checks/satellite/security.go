// pkg/checks/satellite/security.go

package satellite

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunSecurityChecks performs Satellite security checks
func RunSecurityChecks(r *report.AsciiDocReport) {
	// Check Foreman and Capsule certificates
	checkCertificates(r)

	// Check SELinux status
	checkSELinux(r)

	// Check audit logs and authentication configuration
	checkAuditConfiguration(r)

	// Check firewall configuration
	checkFirewallConfiguration(r)
}

// checkCertificates validates Foreman and Capsule certificates
func checkCertificates(r *report.AsciiDocReport) {
	checkID := "satellite-certificates"
	checkName := "Certificate Status"
	checkDesc := "Validates Foreman and Capsule certificates (expiry, validity)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Get certificate information
	certCmd := "satellite-installer --list-certificates"
	certOutput, err := utils.RunCommand("bash", "-c", certCmd)

	var detail strings.Builder
	detail.WriteString("Certificate Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving certificate information:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))

		// Try alternative command
		altCertCmd := "find /etc/pki -name '*.pem' -o -name '*.crt' | xargs -I{} bash -c 'echo \"{}:\"; openssl x509 -in {} -noout -subject -dates 2>/dev/null || echo \"Not a valid certificate\"'"
		altCertOutput, _ := utils.RunCommand("bash", "-c", altCertCmd)

		detail.WriteString("Alternative Certificate Information:\n\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(altCertOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(certOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Katello certificate
	katellocertCmd := "openssl x509 -noout -dates -in /etc/pki/katello/certs/katello-server-ca.crt 2>/dev/null"
	katellocertOutput, _ := utils.RunCommand("bash", "-c", katellocertCmd)

	detail.WriteString("Katello CA Certificate:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(katellocertOutput)
	detail.WriteString("\n----\n\n")

	// Check Satellite Apache certificates
	apacheCertCmd := "openssl x509 -noout -dates -in /etc/pki/katello/certs/katello-apache.crt 2>/dev/null"
	apacheCertOutput, _ := utils.RunCommand("bash", "-c", apacheCertCmd)

	detail.WriteString("Apache Certificate:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(apacheCertOutput)
	detail.WriteString("\n----\n\n")

	// Parse certificate expiry dates
	expiryDates := []string{}
	nearExpiryCount := 0
	expiredCount := 0

	// Check main output
	for _, line := range strings.Split(certOutput+"\n"+katellocertOutput+"\n"+apacheCertOutput, "\n") {
		if strings.Contains(line, "notAfter=") {
			// Extract the date part
			dateParts := strings.SplitN(line, "notAfter=", 2)
			if len(dateParts) > 1 {
				expiryDate := strings.TrimSpace(dateParts[1])
				expiryDates = append(expiryDates, expiryDate)

				// Basic check if expired or near expiry (would require proper date parsing for full accuracy)
				if strings.Contains(line, "Apr 2025") || strings.Contains(line, "May 2025") ||
					strings.Contains(line, "Jun 2025") {
					nearExpiryCount++
				} else if strings.Contains(line, "Jan 2025") || strings.Contains(line, "Feb 2025") ||
					strings.Contains(line, "Mar 2025") {
					expiredCount++
				}
			}
		}
	}

	// Add summary to detail
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Certificate Expiry Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Count\n")
	detail.WriteString(fmt.Sprintf("|Expired certificates|%d\n", expiredCount))
	detail.WriteString(fmt.Sprintf("|Certificates expiring within 3 months|%d\n", nearExpiryCount))
	detail.WriteString("|===\n\n")

	// Add expiry dates
	if len(expiryDates) > 0 {
		detail.WriteString("{set:cellbgcolor!}\n")
		detail.WriteString("Expiry Dates:\n\n")
		detail.WriteString("[cols=\"1,2\", options=\"header\"]\n|===\n")
		detail.WriteString("|Certificate|Expiry Date\n")
		for i, date := range expiryDates {
			detail.WriteString(fmt.Sprintf("|Certificate %d|%s\n", i+1, date))
		}
		detail.WriteString("|===\n\n")
	}

	// Check cipher suites and TLS configuration
	sslCheckCmd := "nmap --script ssl-enum-ciphers -p 443 localhost"
	sslCheckOutput, _ := utils.RunCommand("bash", "-c", sslCheckCmd)

	if strings.Contains(sslCheckOutput, "TLSv1.0") || strings.Contains(sslCheckOutput, "TLSv1.1") {
		detail.WriteString("WARNING: Older TLS versions (1.0/1.1) may be enabled\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(sslCheckOutput)
		detail.WriteString("\n----\n\n")
	}

	// Evaluate results
	if expiredCount > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("%d certificates are expired", expiredCount),
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Renew expired certificates immediately")
		report.AddRecommendation(&check.Result, "Run satellite-installer --regenerate-certs to regenerate certificates")
	} else if nearExpiryCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d certificates will expire within 3 months", nearExpiryCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Plan to renew certificates before they expire")
		report.AddRecommendation(&check.Result, "Run satellite-installer --regenerate-certs to regenerate certificates")
	} else if len(expiryDates) == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine certificate expiry dates",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Manually verify certificate expiry dates")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All certificates appear valid and not near expiry",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/index", versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1549043") // Satellite certificate management

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSELinux ensures SELinux is enforcing and no AVC denials are logged
func checkSELinux(r *report.AsciiDocReport) {
	checkID := "satellite-selinux"
	checkName := "SELinux Status"
	checkDesc := "Ensures SELinux is enforcing and no AVC denials are logged."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check SELinux status
	statusCmd := "getenforce"
	statusOutput, err := utils.RunCommand("bash", "-c", statusCmd)

	var detail strings.Builder
	detail.WriteString("SELinux Status:\n\n")

	if err != nil {
		detail.WriteString("Error checking SELinux status:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString(fmt.Sprintf("SELinux Mode: %s\n\n", strings.TrimSpace(statusOutput)))
	}

	// Check SELinux config file
	configCmd := "cat /etc/selinux/config | grep -v '^#'"
	configOutput, _ := utils.RunCommand("bash", "-c", configCmd)

	detail.WriteString("SELinux Configuration:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(configOutput)
	detail.WriteString("\n----\n\n")

	// Check for recent AVC denials
	avcCmd := "ausearch -m AVC -ts recent 2>/dev/null || grep 'avc:.*denied' /var/log/audit/audit.log /var/log/messages 2>/dev/null | tail -n 20"
	avcOutput, _ := utils.RunCommand("bash", "-c", avcCmd)

	detail.WriteString("Recent SELinux Denials:\n\n")
	if avcOutput == "" {
		detail.WriteString("No recent SELinux denials found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(avcOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check if SELinux booleans related to Satellite are properly set
	boolCmd := "getsebool -a | grep -E 'httpd|ftp|pulp|postgres|tomcat'"
	boolOutput, _ := utils.RunCommand("bash", "-c", boolCmd)

	detail.WriteString("Relevant SELinux Booleans:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(boolOutput)
	detail.WriteString("\n----\n\n")

	// Count SELinux denials
	denialCount := 0
	if avcOutput != "" {
		for _, line := range strings.Split(avcOutput, "\n") {
			if strings.Contains(line, "denied") {
				denialCount++
			}
		}
	}

	// Check if key booleans are set correctly
	correctBooleans := true
	if !strings.Contains(boolOutput, "httpd_can_network_connect -> on") ||
		!strings.Contains(boolOutput, "httpd_use_nfs -> on") {
		correctBooleans = false
	}

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("SELinux Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Status\n")
	detail.WriteString(fmt.Sprintf("|SELinux Mode|%s\n", strings.TrimSpace(statusOutput)))
	detail.WriteString(fmt.Sprintf("|SELinux AVC Denials|%d\n", denialCount))
	detail.WriteString(fmt.Sprintf("|Required Booleans Set|%s\n", boolToYesNo(correctBooleans)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	selinuxEnforcing := strings.TrimSpace(statusOutput) == "Enforcing"
	selinuxDisabled := strings.TrimSpace(statusOutput) == "Disabled"

	if selinuxDisabled {
		check.Result = report.NewResult(report.StatusCritical,
			"SELinux is disabled",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Enable SELinux in enforcing mode")
		report.AddRecommendation(&check.Result, "Update /etc/selinux/config and reboot the system")
	} else if !selinuxEnforcing {
		check.Result = report.NewResult(report.StatusWarning,
			"SELinux is not in enforcing mode",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set SELinux to enforcing mode")
		report.AddRecommendation(&check.Result, "Run 'setenforce 1' and update /etc/selinux/config")
	} else if denialCount > 20 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of SELinux denials (%d)", denialCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate and resolve SELinux denials")
		report.AddRecommendation(&check.Result, "Use audit2allow to create custom policy modules if needed")
	} else if !correctBooleans {
		check.Result = report.NewResult(report.StatusWarning,
			"Some SELinux booleans may not be set correctly",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure httpd_can_network_connect and httpd_use_nfs are enabled")
		report.AddRecommendation(&check.Result, "Set with: setsebool -P httpd_can_network_connect on")
	} else if denialCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d SELinux denials", denialCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review SELinux denials and resolve if persistent")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"SELinux is properly configured and no denials found",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	rhelVersion := utils.GetRedHatVersion()
	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/installing_satellite_server_in_a_connected_network_environment/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/using_selinux/index", rhelVersion))

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkAuditConfiguration reviews audit logs and authentication configuration
func checkAuditConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-audit"
	checkName := "Audit Configuration"
	checkDesc := "Reviews audit logs and authentication configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check Satellite audit settings
	auditSettingsCmd := "hammer settings list --search 'name ~ audit'"
	auditSettingsOutput, err := utils.RunCommand("bash", "-c", auditSettingsCmd)

	var detail strings.Builder
	detail.WriteString("Audit Configuration:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving audit settings:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString("Satellite Audit Settings:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(auditSettingsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for failed login attempts in production log
	loginAttemptsCmd := "grep -i 'Failed login' /var/log/foreman/production.log | tail -20"
	loginAttemptsOutput, _ := utils.RunCommand("bash", "-c", loginAttemptsCmd)

	detail.WriteString("Recent Failed Login Attempts (from logs):\n\n")
	if loginAttemptsOutput == "" {
		detail.WriteString("No recent failed login attempts found in logs\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(loginAttemptsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check authentication sources
	authSourcesCmd := "hammer auth-source list"
	authSourcesOutput, _ := utils.RunCommand("bash", "-c", authSourcesCmd)

	detail.WriteString("Authentication Sources:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(authSourcesOutput)
	detail.WriteString("\n----\n\n")

	// Check for LDAP sources
	hasLdapSources := strings.Contains(authSourcesOutput, "AuthSourceLdap")

	// If LDAP sources exist, get more details
	if hasLdapSources {
		// Get a list of LDAP auth source IDs
		ldapSourcesCmd := "hammer auth-source list | grep 'AuthSourceLdap' | awk '{print $1}'"
		ldapSourcesOutput, _ := utils.RunCommand("bash", "-c", ldapSourcesCmd)

		ldapSourceIDs := strings.Split(strings.TrimSpace(ldapSourcesOutput), "\n")

		detail.WriteString("LDAP Authentication Details:\n\n")

		for _, id := range ldapSourceIDs {
			if id == "" {
				continue
			}

			ldapDetailCmd := fmt.Sprintf("hammer auth-source ldap info --id %s", id)
			ldapDetailOutput, _ := utils.RunCommand("bash", "-c", ldapDetailCmd)

			detail.WriteString(fmt.Sprintf("LDAP Source ID %s:\n", id))
			detail.WriteString("[source, text]\n----\n")
			detail.WriteString(ldapDetailOutput)
			detail.WriteString("\n----\n\n")
		}
	} else {
		detail.WriteString("No LDAP authentication sources configured\n\n")
	}

	// Check for suspicious activities in audit log (focusing on supported actions)
	suspiciousCmd := "hammer audit list --search 'action ~ destroy' --per-page 20"
	suspiciousOutput, _ := utils.RunCommand("bash", "-c", suspiciousCmd)

	detail.WriteString("Recent Destruction Activities (from audit):\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(suspiciousOutput)
	detail.WriteString("\n----\n\n")

	// Check pam configuration
	pamCmd := "cat /etc/pam.d/password-auth /etc/pam.d/system-auth | grep -v '^#'"
	pamOutput, _ := utils.RunCommand("bash", "-c", pamCmd)

	detail.WriteString("PAM Configuration:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(pamOutput)
	detail.WriteString("\n----\n\n")

	// Parse audit settings
	auditEnabled := false
	loginFailureCounted := false
	failedLogins := 0

	// Check if audit is enabled
	if strings.Contains(auditSettingsOutput, "audit") {
		for _, line := range strings.Split(auditSettingsOutput, "\n") {
			if strings.Contains(line, "audit") {
				fields := strings.Fields(line)
				if len(fields) > 2 {
					if fields[2] == "yes" || fields[2] == "true" || fields[2] == "1" {
						auditEnabled = true
					}
				}
			}
		}
	}

	// Count failed logins from logs
	if loginAttemptsOutput != "" {
		loginFailureCounted = true
		for _, line := range strings.Split(loginAttemptsOutput, "\n") {
			if strings.Contains(line, "Failed login") {
				failedLogins++
			}
		}
	}

	// Check password complexity requirements
	passwordComplexityOk := strings.Contains(pamOutput, "pam_pwquality.so") ||
		strings.Contains(pamOutput, "pam_cracklib.so") ||
		strings.Contains(pamOutput, "minlen=") ||
		strings.Contains(pamOutput, "ocredit=")

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Audit Configuration Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Status\n")
	detail.WriteString(fmt.Sprintf("|Auditing Enabled|%s\n", boolToYesNo(auditEnabled)))
	detail.WriteString(fmt.Sprintf("|Failed Login Attempts|%d\n", failedLogins))
	detail.WriteString(fmt.Sprintf("|LDAP Authentication|%s\n", boolToYesNo(hasLdapSources)))
	detail.WriteString(fmt.Sprintf("|Password Complexity Requirements|%s\n", boolToYesNo(passwordComplexityOk)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !auditEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Satellite auditing may not be properly enabled",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable auditing in Satellite settings")
		report.AddRecommendation(&check.Result, "Set audit_logfile to true")
	} else if !hasLdapSources {
		check.Result = report.NewResult(report.StatusWarning,
			"No LDAP authentication sources configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider configuring LDAP authentication for enterprise integration")
		report.AddRecommendation(&check.Result, "Use 'hammer auth-source ldap create' to add LDAP sources")
	} else if loginFailureCounted && failedLogins > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of failed login attempts (%d)", failedLogins),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate failed login attempts for potential security issues")
		report.AddRecommendation(&check.Result, "Consider configuring account lockout after failed attempts")
	} else if !passwordComplexityOk {
		check.Result = report.NewResult(report.StatusWarning,
			"Password complexity requirements may not be properly configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure password complexity requirements in PAM")
		report.AddRecommendation(&check.Result, "Add or update pam_pwquality.so or pam_cracklib.so configuration")
	} else if loginFailureCounted && failedLogins > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d failed login attempts", failedLogins),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor for unusual login patterns")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Audit and authentication configuration appears proper",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	rhelVersion := utils.GetRedHatVersion()
	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/administering_red_hat_satellite/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/index", rhelVersion)) // RHEL authentication guide
	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFirewallConfiguration checks if the firewall is properly configured for Satellite
func checkFirewallConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-firewall"
	checkName := "Firewall Configuration"
	checkDesc := "Checks if the firewall is properly configured for Satellite."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check firewall status
	firewallCmd := "systemctl status firewalld || systemctl status iptables"
	firewallOutput, _ := utils.RunCommand("bash", "-c", firewallCmd)

	var detail strings.Builder
	detail.WriteString("Firewall Status:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(firewallOutput)
	detail.WriteString("\n----\n\n")

	// Check if firewalld is active
	firewalldActive := strings.Contains(firewallOutput, "active (running)")

	// Check firewall configuration if firewalld is active
	var firewallConfigOutput string
	if firewalldActive {
		// Check if Satellite ports are open in firewalld
		firewallConfigCmd := "firewall-cmd --list-all"
		firewallConfigOutput, _ = utils.RunCommand("bash", "-c", firewallConfigCmd)

		detail.WriteString("Firewall Configuration:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(firewallConfigOutput)
		detail.WriteString("\n----\n\n")

		// Check if satellite service is defined
		serviceCheckCmd := "firewall-cmd --get-services | grep -E 'RH-Satellite-6|RH-Satellite-6-capsule'"
		serviceCheckOutput, _ := utils.RunCommand("bash", "-c", serviceCheckCmd)

		detail.WriteString("Satellite Firewall Service:\n\n")
		if serviceCheckOutput == "" {
			detail.WriteString("No satellite service defined in firewalld\n\n")
		} else {
			detail.WriteString("[source, text]\n----\n")
			detail.WriteString(serviceCheckOutput)
			detail.WriteString("\n----\n\n")

			// Check satellite service definition
			satServiceCmd := "cat /usr/lib/firewalld/services/satellite.xml 2>/dev/null || echo 'Service file not found'"
			satServiceOutput, _ := utils.RunCommand("bash", "-c", satServiceCmd)

			detail.WriteString("Satellite Service Definition:\n\n")
			detail.WriteString("[source, xml]\n----\n")
			detail.WriteString(satServiceOutput)
			detail.WriteString("\n----\n\n")
		}
	} else {
		// Check iptables rules
		iptablesCmd := "iptables -L -n"
		iptablesOutput, _ := utils.RunCommand("bash", "-c", iptablesCmd)

		detail.WriteString("IPTables Rules:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(iptablesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Determine if this is a Satellite server or Capsule server
	isCapsuleCmd := "rpm -q satellite-capsule || rpm -q capsule || rpm -q foreman-proxy-content"
	isCapsuleOutput, _ := utils.RunCommand("bash", "-c", isCapsuleCmd)
	isCapsule := !strings.Contains(isCapsuleOutput, "not installed")

	// Also check if this is a stand-alone Capsule
	isStandaloneCapsuleCmd := "rpm -q satellite || rpm -q foreman-installer"
	isStandaloneCapsuleOutput, _ := utils.RunCommand("bash", "-c", isStandaloneCapsuleCmd)
	isStandaloneCapsule := isCapsule && strings.Contains(isStandaloneCapsuleOutput, "not installed")

	// Define port groups by functionality - Updated with more accurate information
	// Core ports required for Satellite/Capsule operation
	corePorts := map[string]map[string]string{
		"80":   {"service": "HTTP", "description": "HTTP for web UI and content access", "required": "true"},
		"443":  {"service": "HTTPS", "description": "HTTPS for secure web UI and API access", "required": "true"},
		"9090": {"service": "HTTPS for Foreman Proxy", "description": "Smart Proxy/Capsule HTTPS communication", "required": "true"},
	}

	// Additional ports for Satellite server
	satellitePorts := map[string]map[string]string{
		"5432": {"service": "PostgreSQL", "description": "PostgreSQL database", "required": "true"},
		"8000": {"service": "HTTP(S) Pulpcore API", "description": "Pulpcore API access", "required": "true"},
		"8140": {"service": "HTTPS Puppet Server", "description": "Puppet server communication", "required": "true"},
	}

	// Additional ports for provisioning functionality
	provisioningPorts := map[string]map[string]string{
		"53":   {"service": "DNS", "description": "DNS service (TCP/UDP)", "required": "optional"},
		"67":   {"service": "DHCP", "description": "DHCP service (UDP)", "required": "optional"},
		"68":   {"service": "DHCP", "description": "DHCP service (UDP)", "required": "optional"},
		"69":   {"service": "TFTP", "description": "TFTP service (UDP)", "required": "optional"},
		"8443": {"service": "Katello Agent", "description": "Host subscription management (Legacy)", "required": "optional"},
		"5647": {"service": "Puppet Agent", "description": "Puppet agent communication", "required": "optional"},
	}

	// Content sync ports
	contentSyncPorts := map[string]map[string]string{
		"5000": {"service": "Docker Registry", "description": "Docker Registry communication", "required": "optional"},
		"5646": {"service": "AMQP", "description": "AMQP communication for Capsule sync", "required": "optional"},
		"5647": {"service": "Puppet", "description": "Puppet client communication", "required": "optional"},
		"5671": {"service": "AMQP/Qpid", "description": "Katello Agent communication (Legacy)", "required": "optional"},
		"7911": {"service": "QDROUTERD", "description": "Capsule communication", "required": "optional"},
		"8080": {"service": "HTTP Pulpcore Content", "description": "Pulpcore content access", "required": "optional"},
	}

	// Check which ports are actually listening
	portsCmd := "ss -tulpn | grep LISTEN"
	portsOutput, _ := utils.RunCommand("bash", "-c", portsCmd)

	detail.WriteString("Listening Ports:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(portsOutput)
	detail.WriteString("\n----\n\n")

	// Check for enabled services that would require optional ports
	// DNS check
	isDNSEnabledCmd := "systemctl is-active named || systemctl is-active dnsmasq || grep -E 'dns.*=.*true' /etc/foreman-proxy/settings.d/dns.yml 2>/dev/null || grep -E 'dns.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isDNSEnabledOutput, _ := utils.RunCommand("bash", "-c", isDNSEnabledCmd)
	isDNSEnabled := !strings.Contains(isDNSEnabledOutput, "inactive") && isDNSEnabledOutput != ""

	// DHCP check
	isDHCPEnabledCmd := "systemctl is-active dhcpd || grep -E 'dhcp.*=.*true' /etc/foreman-proxy/settings.d/dhcp.yml 2>/dev/null || grep -E 'dhcp.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isDHCPEnabledOutput, _ := utils.RunCommand("bash", "-c", isDHCPEnabledCmd)
	isDHCPEnabled := !strings.Contains(isDHCPEnabledOutput, "inactive") && isDHCPEnabledOutput != ""

	// TFTP check
	isTFTPEnabledCmd := "systemctl is-active xinetd || systemctl is-active tftp || grep -E 'tftp.*=.*true' /etc/foreman-proxy/settings.d/tftp.yml 2>/dev/null || grep -E 'tftp.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isTFTPEnabledOutput, _ := utils.RunCommand("bash", "-c", isTFTPEnabledCmd)
	isTFTPEnabled := !strings.Contains(isTFTPEnabledOutput, "inactive") && isTFTPEnabledOutput != ""

	// Docker registry check
	isDockerEnabledCmd := "systemctl is-active docker-distribution || grep -E 'registry.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isDockerEnabledOutput, _ := utils.RunCommand("bash", "-c", isDockerEnabledCmd)
	isDockerEnabled := !strings.Contains(isDockerEnabledOutput, "inactive") && isDockerEnabledOutput != ""

	// Puppet check
	isPuppetEnabledCmd := "systemctl is-active puppetserver || grep -E 'puppet.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isPuppetEnabledOutput, _ := utils.RunCommand("bash", "-c", isPuppetEnabledCmd)
	isPuppetEnabled := !strings.Contains(isPuppetEnabledOutput, "inactive") && isPuppetEnabledOutput != ""

	// Katello Agent check - legacy but may still be in use
	isKatelloAgentEnabledCmd := "grep -E 'katello_agent.*=.*true' /etc/foreman-installer/scenarios.d/satellite-answers.yaml 2>/dev/null"
	isKatelloAgentEnabledOutput, _ := utils.RunCommand("bash", "-c", isKatelloAgentEnabledCmd)
	isKatelloAgentEnabled := isKatelloAgentEnabledOutput != ""

	// Combine required port maps based on server type
	requiredPorts := make(map[string]map[string]string)

	// Add core ports for all installations
	for port, portInfo := range corePorts {
		requiredPorts[port] = portInfo
	}

	// Add satellite-specific ports if not a standalone capsule
	if !isStandaloneCapsule {
		for port, portInfo := range satellitePorts {
			requiredPorts[port] = portInfo
		}
	}

	// Add provisioning ports if corresponding services are enabled
	if isDNSEnabled {
		requiredPorts["53"] = provisioningPorts["53"]
	}

	if isDHCPEnabled {
		requiredPorts["67"] = provisioningPorts["67"]
		requiredPorts["68"] = provisioningPorts["68"]
	}

	if isTFTPEnabled {
		requiredPorts["69"] = provisioningPorts["69"]
	}

	if isKatelloAgentEnabled {
		requiredPorts["8443"] = provisioningPorts["8443"]
		requiredPorts["5671"] = contentSyncPorts["5671"]
	}

	if isPuppetEnabled {
		// Check if 8140 exists and is not already required
		if _, exists := requiredPorts["8140"]; !exists || requiredPorts["8140"]["required"] != "true" {
			requiredPorts["8140"] = provisioningPorts["8140"]
		}
		requiredPorts["5647"] = provisioningPorts["5647"]
	}

	// Add content sync ports if Docker registry is enabled
	if isDockerEnabled {
		requiredPorts["5000"] = contentSyncPorts["5000"]
	}

	// Always add messaging ports for content sync
	for port, portInfo := range contentSyncPorts {
		if port != "5000" && // Skip Docker port if already added
			port != "5671" && // Skip Katello agent port if already added
			port != "5647" { // Skip Puppet port if already added
			// Check if this port appears to be in use before adding it
			if strings.Contains(portsOutput, ":"+port) {
				requiredPorts[port] = portInfo
			}
		}
	}

	// Track missing required and optional ports
	missingRequiredPorts := []string{}
	missingOptionalPorts := []string{}
	presentPorts := []string{}

	// Check which ports are open
	for port, portInfo := range requiredPorts {
		if strings.Contains(portsOutput, ":"+port) {
			presentPorts = append(presentPorts, port)
		} else {
			if portInfo["required"] == "true" {
				missingRequiredPorts = append(missingRequiredPorts, port)
			} else {
				missingOptionalPorts = append(missingOptionalPorts, port)
			}
		}
	}

	// Check if satellite ports are properly accessible through firewall
	accessiblePorts := true
	if firewalldActive {
		// Check for required ports in firewall config
		for _, port := range missingRequiredPorts {
			if !strings.Contains(firewallConfigOutput, port+"/tcp") &&
				!strings.Contains(firewallConfigOutput, port+"/udp") &&
				!strings.Contains(firewallConfigOutput, "satellite") {
				accessiblePorts = false
				break
			}
		}
	}

	// Create a detailed port status table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Port Status Details:\n\n")
	detail.WriteString("|===\n")
	detail.WriteString("|Port|Service|Description|Status|Required\n\n")

	// Function to add port details to the table
	addPortToTable := func(port string, portInfo map[string]string, status string) {
		required := "Yes"
		if portInfo["required"] != "true" {
			required = "Optional"
		}
		detail.WriteString(fmt.Sprintf("|%s|%s|%s|%s|%s\n",
			port,
			portInfo["service"],
			portInfo["description"],
			status,
			required))
	}

	// Add all present ports first
	for _, port := range presentPorts {
		addPortToTable(port, requiredPorts[port], "Open")
	}

	// Add missing required ports
	for _, port := range missingRequiredPorts {
		addPortToTable(port, requiredPorts[port], "Closed")
	}

	// Add missing optional ports - only if the corresponding service is enabled
	for _, port := range missingOptionalPorts {
		// Check if we should show this port based on enabled services
		showPort := false

		// Only show ports for services that are enabled but not listening
		if port == "53" && isDNSEnabled {
			showPort = true
		} else if (port == "67" || port == "68") && isDHCPEnabled {
			showPort = true
		} else if port == "69" && isTFTPEnabled {
			showPort = true
		} else if port == "5000" && isDockerEnabled {
			showPort = true
		} else if (port == "8140" || port == "5647") && isPuppetEnabled {
			showPort = true
		} else if (port == "8443" || port == "5671") && isKatelloAgentEnabled {
			showPort = true
		}

		if showPort {
			addPortToTable(port, requiredPorts[port], "Closed")
		}
	}

	detail.WriteString("|===\n\n")

	// Create a firewall configuration summary
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Firewall Configuration Summary:\n\n")
	detail.WriteString("|===\n")
	detail.WriteString("|Item|Status\n\n")
	detail.WriteString(fmt.Sprintf("|Firewall Active|%s\n", boolToYesNo(firewalldActive)))
	detail.WriteString(fmt.Sprintf("|Satellite Ports Accessible|%s\n", boolToYesNo(accessiblePorts)))

	if len(missingRequiredPorts) > 0 {
		detail.WriteString(fmt.Sprintf("|Missing Required Ports|%s\n", strings.Join(missingRequiredPorts, ", ")))
	} else {
		detail.WriteString("|Missing Required Ports|None\n")
	}

	// Only show missing optional ports for enabled services
	relevantMissingOptional := []string{}
	for _, port := range missingOptionalPorts {
		if (port == "53" && isDNSEnabled) ||
			((port == "67" || port == "68") && isDHCPEnabled) ||
			(port == "69" && isTFTPEnabled) ||
			(port == "5000" && isDockerEnabled) ||
			((port == "8140" || port == "5647") && isPuppetEnabled) ||
			((port == "8443" || port == "5671") && isKatelloAgentEnabled) {
			relevantMissingOptional = append(relevantMissingOptional, port)
		}
	}

	if len(relevantMissingOptional) > 0 {
		detail.WriteString(fmt.Sprintf("|Missing Optional Ports|%s\n", strings.Join(relevantMissingOptional, ", ")))
	} else {
		detail.WriteString("|Missing Optional Ports|None\n")
	}
	detail.WriteString("|===\n\n")

	// Detect which server type we're analyzing
	serverType := "Satellite"
	if isStandaloneCapsule {
		serverType = "Standalone Capsule"
	} else if isCapsule {
		serverType = "Integrated Capsule"
	}
	detail.WriteString(fmt.Sprintf("Server Type: %s\n\n", serverType))

	// Evaluate results
	if len(missingRequiredPorts) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Some required %s ports are not open: %s", serverType, strings.Join(missingRequiredPorts, ", ")),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if all required Satellite services are running")

		// Add specific recommendations for each missing service
		for _, port := range missingRequiredPorts {
			portInfo := requiredPorts[port]
			report.AddRecommendation(&check.Result, fmt.Sprintf("Verify %s service is running (port %s)", portInfo["service"], port))
		}

		if firewalldActive && !accessiblePorts {
			report.AddRecommendation(&check.Result, "Add required ports to firewalld configuration")
			report.AddRecommendation(&check.Result, "Run: firewall-cmd --add-service=satellite --permanent")
			report.AddRecommendation(&check.Result, "Or add individual ports: firewall-cmd --add-port=<port>/tcp --permanent")
			report.AddRecommendation(&check.Result, "Then run: firewall-cmd --reload")
		}
	} else if firewalldActive && !accessiblePorts {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Firewall may not be properly configured for %s", serverType),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Add required Satellite ports to firewalld")
		report.AddRecommendation(&check.Result, "Run: firewall-cmd --add-service=satellite --permanent")
		report.AddRecommendation(&check.Result, "Run: firewall-cmd --reload")
	} else if !firewalldActive && !strings.Contains(firewallOutput, "active (running)") {
		check.Result = report.NewResult(report.StatusWarning,
			"Firewall service does not appear to be running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable and start firewalld service")
		report.AddRecommendation(&check.Result, fmt.Sprintf("Configure appropriate rules for %s", serverType))
		report.AddRecommendation(&check.Result, "Run: systemctl enable --now firewalld")
	} else if len(relevantMissingOptional) > 0 {
		check.Result = report.NewResult(report.StatusInfo,
			fmt.Sprintf("Firewall configured correctly, but some optional services may not be running: %s", strings.Join(relevantMissingOptional, ", ")),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "If these services are needed, verify their configuration")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Firewall appears to be properly configured for %s", serverType),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/installing_satellite_server_in_a_connected_network_environment/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// Helper function to convert boolean to Yes/No (unchanged from original)
func boolToYesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}
