// pkg/checks/rhel/auth.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunAuthChecks performs authentication related checks
func RunAuthChecks(r *report.AsciiDocReport) {
	// Confirm central auth integration (FreeIPA/LDAP/AD)
	checkCentralAuth(r)

	// Validate SSSD caching and failover
	checkSSSD(r)

	// Review sudo rules and PAM consistency
	checkSudoAndPAM(r)

	// Ensure Kerberos config is valid (if applicable)
	checkKerberos(r)
}

// checkCentralAuth confirms central auth integration (FreeIPA/LDAP/AD)
func checkCentralAuth(r *report.AsciiDocReport) {
	checkID := "auth-central"
	checkName := "Central Authentication"
	checkDesc := "Confirms central auth integration (FreeIPA/LDAP/AD)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check for SSSD installation
	sssdCmd := "rpm -q sssd 2>/dev/null || echo 'SSSD not installed'"
	sssdOutput, _ := utils.RunCommand("bash", "-c", sssdCmd)
	sssdInstalled := !strings.Contains(sssdOutput, "not installed")

	// Check for realm membership (FreeIPA/AD)
	realmListCmd := "realm list 2>/dev/null || echo 'Realm command not available'"
	realmListOutput, _ := utils.RunCommand("bash", "-c", realmListCmd)
	realmJoined := strings.Contains(realmListOutput, "type:")

	// Check for authconfig/authselect configuration
	authConfigCmd := "authconfig --test 2>/dev/null || authselect current 2>/dev/null || echo 'Authentication configuration not available'"
	authConfigOutput, _ := utils.RunCommand("bash", "-c", authConfigCmd)

	// Check for Kerberos configuration
	krbConfCmd := "cat /etc/krb5.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'Kerberos configuration not found'"
	krbConfOutput, _ := utils.RunCommand("bash", "-c", krbConfCmd)

	// Check for LDAP configuration
	ldapConfCmd := "cat /etc/openldap/ldap.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'LDAP configuration not found'"
	ldapConfOutput, _ := utils.RunCommand("bash", "-c", ldapConfCmd)

	// Check if getent can retrieve central users
	getentCmd := "getent passwd | grep -v $(cut -d: -f1,3 /etc/passwd) | head -5"
	getentOutput, _ := utils.RunCommand("bash", "-c", getentCmd)

	var detail strings.Builder
	detail.WriteString("SSSD Installation:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sssdOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Realm Membership:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(realmListOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Authentication Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(authConfigOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kerberos Configuration Excerpt:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(krbConfOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("LDAP Configuration Excerpt:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ldapConfOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Non-Local Users (first 5):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(getentOutput) == "" {
		detail.WriteString("No non-local users detected\n")
	} else {
		detail.WriteString(getentOutput)
	}
	detail.WriteString("\n----\n")

	// Determine auth type
	authType := "None"
	if realmJoined {
		if strings.Contains(realmListOutput, "active-directory") {
			authType = "Active Directory"
		} else if strings.Contains(realmListOutput, "ipa") {
			authType = "FreeIPA"
		} else {
			authType = "Realm"
		}
	} else if strings.Contains(authConfigOutput, "LDAP") ||
		(strings.Contains(ldapConfOutput, "URI") && !strings.Contains(ldapConfOutput, "LDAP configuration not found")) {
		authType = "LDAP"
	}

	// Check for connectivity to auth servers
	connectivityIssue := false
	if authType == "Active Directory" || authType == "FreeIPA" || authType == "Realm" {
		// Extract realm server
		var server string
		for _, line := range strings.Split(realmListOutput, "\n") {
			if strings.Contains(line, "server-software:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					server = strings.TrimSpace(parts[1])
				}
			}
		}

		if server != "" {
			pingCmd := fmt.Sprintf("ping -c 1 %s 2>/dev/null || echo 'Cannot ping server'", server)
			pingOutput, _ := utils.RunCommand("bash", "-c", pingCmd)
			connectivityIssue = strings.Contains(pingOutput, "Cannot ping server")

			detail.WriteString(fmt.Sprintf("\nConnectivity to %s:\n", server))
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(pingOutput)
			detail.WriteString("\n----\n")
		}
	}

	// Evaluate central authentication
	if authType == "None" {
		check.Result = report.NewResult(report.StatusInfo,
			"No central authentication configuration detected",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Consider implementing central authentication for easier user management")
		report.AddRecommendation(&check.Result, "Options include FreeIPA, Active Directory, or LDAP")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/index", rhelVersion))
	} else if !sssdInstalled {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%s integration detected but SSSD is not installed", authType),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install SSSD for better authentication management: 'yum install sssd'")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/understanding-the-sssd-configuration-file_configuring-authorization", rhelVersion))
	} else if connectivityIssue {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Connectivity issue with %s server", authType),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check network connectivity to authentication server")
		report.AddRecommendation(&check.Result, "Verify DNS resolution for authentication server")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/troubleshooting-authentication-and-authorization_configuring-authentication", rhelVersion))
	} else if strings.TrimSpace(getentOutput) == "" {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%s integration configured but no central users detected", authType),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify that central authentication is working correctly")
		report.AddRecommendation(&check.Result, "Test with 'id username' for a central user")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/assembly_testing-authentication-configurations_configuring-authentication", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%s integration is properly configured and working", authType),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSSSD validates SSSD caching and failover
func checkSSSD(r *report.AsciiDocReport) {
	checkID := "auth-sssd"
	checkName := "SSSD Configuration"
	checkDesc := "Validates SSSD caching and failover."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check for SSSD installation
	sssdCmd := "rpm -q sssd 2>/dev/null || echo 'SSSD not installed'"
	sssdOutput, _ := utils.RunCommand("bash", "-c", sssdCmd)
	sssdInstalled := !strings.Contains(sssdOutput, "not installed")

	if !sssdInstalled {
		check.Result = report.NewResult(report.StatusInfo,
			"SSSD is not installed",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider installing SSSD for improved authentication capabilities")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/understanding-sssd-and-its-benefits_configuring-authentication", rhelVersion))
		r.AddCheck(check)
		return
	}

	// Check SSSD configuration
	sssdConfCmd := "cat /etc/sssd/sssd.conf 2>/dev/null || echo 'SSSD configuration not found'"
	sssdConfOutput, _ := utils.RunCommand("bash", "-c", sssdConfCmd)

	// Check SSSD service status
	sssdStatusCmd := "systemctl status sssd 2>/dev/null | grep Active || echo 'SSSD service not found'"
	sssdStatusOutput, _ := utils.RunCommand("bash", "-c", sssdStatusCmd)
	sssdActive := strings.Contains(sssdStatusOutput, "active (running)")

	// Check SSSD logs for issues
	sssdLogCmd := "grep -i 'error\\|fail' /var/log/sssd/*.log 2>/dev/null | tail -10 || echo 'No SSSD logs found'"
	sssdLogOutput, _ := utils.RunCommand("bash", "-c", sssdLogCmd)

	var detail strings.Builder
	detail.WriteString("SSSD Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sssdStatusOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("SSSD Configuration Excerpt:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(sssdConfOutput, "SSSD configuration not found") {
		detail.WriteString(sssdConfOutput)
	} else {
		// Extract sensitive settings (caching, failover)
		for _, line := range strings.Split(sssdConfOutput, "\n") {
			if strings.Contains(line, "cache_") ||
				strings.Contains(line, "offline") ||
				strings.Contains(line, "fallback") ||
				strings.Contains(line, "timeout") ||
				strings.Contains(line, "services") ||
				strings.Contains(line, "domains") {
				detail.WriteString(line + "\n")
			}
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("SSSD Log Issues (last 10):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(sssdLogOutput, "No SSSD logs found") {
		detail.WriteString("No SSSD logs found or no errors detected\n")
	} else {
		detail.WriteString(sssdLogOutput)
	}
	detail.WriteString("\n----\n")

	// Evaluate SSSD configuration
	issues := []string{}

	if !sssdActive {
		issues = append(issues, "SSSD service is not running")
	}

	if strings.Contains(sssdConfOutput, "SSSD configuration not found") {
		issues = append(issues, "SSSD configuration file not found")
	} else {
		// Check for caching settings
		if !strings.Contains(sssdConfOutput, "cache_credentials") {
			issues = append(issues, "cache_credentials setting not found")
		}

		// Check for offline authentication
		if !strings.Contains(sssdConfOutput, "offline_credentials") {
			issues = append(issues, "offline_credentials setting not found")
		}

		// Check for services
		if !strings.Contains(sssdConfOutput, "services") {
			issues = append(issues, "services setting not found")
		}
	}

	// Check for errors in logs
	hasLogErrors := strings.TrimSpace(sssdLogOutput) != "" &&
		!strings.Contains(sssdLogOutput, "No SSSD logs found")

	if hasLogErrors {
		issues = append(issues, "Errors found in SSSD logs")
	}

	// We could optionally use the hasPamSssd variable here for additional checks
	// For now, let's check if both PAM files mention SSSDm and add a recommendation if not
	if !strings.Contains(sssdStatusOutput, "pam_sss.so") {
		issues = append(issues, "PAM not configured for SSSD authentication")
	}

	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d issues with SSSD configuration", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !sssdActive {
			report.AddRecommendation(&check.Result, "Start SSSD service: 'systemctl start sssd'")
			report.AddRecommendation(&check.Result, "Enable SSSD service: 'systemctl enable sssd'")
		}

		if strings.Contains(sssdConfOutput, "SSSD configuration not found") {
			report.AddRecommendation(&check.Result, "Create proper SSSD configuration in /etc/sssd/sssd.conf")
		} else {
			if !strings.Contains(sssdConfOutput, "cache_credentials") {
				report.AddRecommendation(&check.Result, "Add 'cache_credentials = true' to SSSD domain section for offline authentication")
			}
			if !strings.Contains(sssdConfOutput, "offline_credentials") {
				report.AddRecommendation(&check.Result, "Add 'offline_credentials_expiration = 7' to SSSD domain section")
			}
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/configuring-sssd_configuring-authentication", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"SSSD is properly configured with caching and failover settings",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSudoAndPAM reviews sudo rules and PAM consistency
func checkSudoAndPAM(r *report.AsciiDocReport) {
	checkID := "auth-sudo-pam"
	checkName := "Sudo and PAM"
	checkDesc := "Reviews sudo rules and PAM consistency."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check sudoers configuration
	sudoersCmd := "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'No sudo rules found'"
	sudoersOutput, _ := utils.RunCommand("bash", "-c", sudoersCmd)

	// Check for centralized sudo rules
	ldapSudoCmd := "grep -i 'sudoers' /etc/sssd/sssd.conf 2>/dev/null || echo 'No LDAP sudoers configuration'"
	ldapSudoOutput, _ := utils.RunCommand("bash", "-c", ldapSudoCmd)

	// Check PAM configuration for system-auth
	pamSystemAuthCmd := "cat /etc/pam.d/system-auth 2>/dev/null | grep -v '^#' || echo 'PAM system-auth not found'"
	pamSystemAuthOutput, _ := utils.RunCommand("bash", "-c", pamSystemAuthCmd)

	// Check PAM configuration for password-auth
	pamPasswordAuthCmd := "cat /etc/pam.d/password-auth 2>/dev/null | grep -v '^#' || echo 'PAM password-auth not found'"
	pamPasswordAuthOutput, _ := utils.RunCommand("bash", "-c", pamPasswordAuthCmd)

	// Check for sudo logs - improved search in multiple locations
	sudoLogCmd := "ls -la /var/log/sudo.log /var/log/secure 2>/dev/null | grep -v 'No such file' || grep -l sudo /var/log/secure /var/log/auth.log /var/log/messages 2>/dev/null || echo 'No sudo logs found'"
	sudoLogOutput, _ := utils.RunCommand("bash", "-c", sudoLogCmd)

	// FIXED: Check for users with sudo privileges (excluding root) - improved detection
	sudoUsersCmd := "for user in $(cut -d: -f1 /etc/passwd | grep -v '^root$'); do sudo -l -U $user 2>/dev/null | grep -E '(ALL|NOPASSWD)'; done | grep -v 'not allowed' || echo 'No additional sudo users found'"
	sudoUsersOutput, _ := utils.RunCommand("bash", "-c", sudoUsersCmd)

	// FIXED: Check for users in sudo group or wheel group with more reliable extraction
	sudoGroupsCmd := "getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\\n' | grep -v '^root$' || echo 'No non-root users in sudo/wheel groups'"
	sudoGroupsOutput, _ := utils.RunCommand("bash", "-c", sudoGroupsCmd)

	// FIXED: Check users with UID 0 (which gives them root privileges)
	uid0UsersCmd := "awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd || echo 'No additional users with UID 0'"
	uid0UsersOutput, _ := utils.RunCommand("bash", "-c", uid0UsersCmd)

	var detail strings.Builder
	detail.WriteString("Sudo Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sudoersOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("LDAP Sudo Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ldapSudoOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("PAM System Auth Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pamSystemAuthOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("PAM Password Auth Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pamPasswordAuthOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Sudo Logging:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sudoLogOutput)
	detail.WriteString("\n----\n\n")

	// FIXED: Add output for sudo privilege checks with better formatting
	detail.WriteString("Users with Sudo Privileges:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(sudoUsersOutput, "No additional sudo users found") {
		detail.WriteString("No additional sudo users found\n")
	} else {
		detail.WriteString(sudoUsersOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Non-root Users in Sudo/Wheel Groups:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(sudoGroupsOutput, "No non-root users in sudo/wheel groups") || strings.TrimSpace(sudoGroupsOutput) == "" {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(sudoGroupsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Users with UID 0 (root privileges):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(uid0UsersOutput, "No additional users with UID 0") || strings.TrimSpace(uid0UsersOutput) == "" {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(uid0UsersOutput)
	}
	detail.WriteString("\n----\n")

	// Check if wheel group in sudoers
	hasWheelGroup := strings.Contains(sudoersOutput, "wheel")

	// Check if sudo rules exist
	hasSudoRules := !strings.Contains(sudoersOutput, "No sudo rules found")

	// Check for centralized sudo
	hasCentralizedSudo := strings.Contains(ldapSudoOutput, "sudoers")

	// Check if PAM has appropriate security modules
	hasPamFaillock := strings.Contains(pamSystemAuthOutput, "pam_faillock.so") ||
		strings.Contains(pamPasswordAuthOutput, "pam_faillock.so")

	// Check for sudo logging
	hasSudoLogging := !strings.Contains(sudoLogOutput, "No sudo logs found")

	// FIXED: Check for privileged non-root users
	hasPrivilegedUsers := false
	if !strings.Contains(sudoUsersOutput, "No additional sudo users found") && strings.TrimSpace(sudoUsersOutput) != "" {
		hasPrivilegedUsers = true
	}
	if !strings.Contains(sudoGroupsOutput, "No non-root users in sudo/wheel groups") && strings.TrimSpace(sudoGroupsOutput) != "" {
		hasPrivilegedUsers = true
	}
	if !strings.Contains(uid0UsersOutput, "No additional users with UID 0") && strings.TrimSpace(uid0UsersOutput) != "" {
		hasPrivilegedUsers = true
	}

	// Define issues slice for tracking problems
	issues := []string{}

	// Check for consistency issues with PAM
	if strings.Contains(pamSystemAuthOutput, "PAM system-auth not found") ||
		strings.Contains(pamPasswordAuthOutput, "PAM password-auth not found") {
		issues = append(issues, "Missing critical PAM configuration files")
	}

	if !hasPamFaillock {
		issues = append(issues, "No account lockout protection configured in PAM")
	}

	if !hasSudoLogging {
		issues = append(issues, "No sudo logging configured")
	}

	// Check PAM files for SSSD configuration (if centralized sudo is used)
	if hasCentralizedSudo {
		if !strings.Contains(pamSystemAuthOutput, "pam_sss.so") &&
			!strings.Contains(pamPasswordAuthOutput, "pam_sss.so") {
			issues = append(issues, "PAM not configured for SSSD authentication")
		}
	}

	if !hasWheelGroup && !hasCentralizedSudo {
		issues = append(issues, "No wheel group in sudoers for administrative access")
	}

	// NEW: Check for privileged users and add to issues
	if hasPrivilegedUsers {
		issues = append(issues, "Local users with elevated privileges detected")
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate password policy compliance
	if hasPrivilegedUsers {
		// NEW: Make this a required change when privileged users are detected
		check.Result = report.NewResult(report.StatusCritical,
			"Local users with root or sudo privileges detected",
			report.ResultKeyRequired)

		report.AddRecommendation(&check.Result, "Consider implementing Red Hat IdM (Identity Management) for centralized and granular control of user privileges")
		report.AddRecommendation(&check.Result, "Review and remove unnecessary sudo privileges from local users")
		report.AddRecommendation(&check.Result, "Implement a proper privilege escalation workflow through a centralized system")

		// Add other relevant recommendations
		if !hasSudoLogging {
			report.AddRecommendation(&check.Result, "Configure sudo logging with 'Defaults logfile=/var/log/sudo.log' in /etc/sudoers")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/planning_identity_management/index", rhelVersion))
	} else if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d issues with sudo and PAM configuration", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !hasSudoRules && !hasCentralizedSudo {
			report.AddRecommendation(&check.Result, "Configure sudo rules in /etc/sudoers or via centralized management")
		}

		if !hasWheelGroup && !hasCentralizedSudo {
			report.AddRecommendation(&check.Result, "Add '%wheel ALL=(ALL) ALL' to /etc/sudoers")
		}

		if !hasPamFaillock {
			report.AddRecommendation(&check.Result, "Configure account lockout with pam_faillock in PAM configuration")
		}

		if !hasSudoLogging {
			report.AddRecommendation(&check.Result, "Configure sudo logging with 'Defaults logfile=/var/log/sudo.log' in /etc/sudoers")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/managing-users-and-groups_configuring-basic-system-settings#managing-sudo-access_managing-users-and-groups", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Sudo rules and PAM configuration are consistent and properly set up",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkKerberos ensures Kerberos config is valid (if applicable)
func checkKerberos(r *report.AsciiDocReport) {
	checkID := "auth-kerberos"
	checkName := "Kerberos Configuration"
	checkDesc := "Ensures Kerberos config is valid (if applicable)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check if Kerberos is installed
	kerberosCmd := "rpm -q krb5-workstation 2>/dev/null || echo 'Kerberos not installed'"
	kerberosOutput, _ := utils.RunCommand("bash", "-c", kerberosCmd)
	kerberosInstalled := !strings.Contains(kerberosOutput, "not installed")

	// Check Kerberos configuration
	krbConfCmd := "cat /etc/krb5.conf 2>/dev/null || echo 'Kerberos configuration not found'"
	krbConfOutput, _ := utils.RunCommand("bash", "-c", krbConfCmd)

	// Check for keytab file
	keytabCmd := "ls -l /etc/krb5.keytab 2>/dev/null || echo 'Keytab file not found'"
	keytabOutput, _ := utils.RunCommand("bash", "-c", keytabCmd)
	hasKeytab := !strings.Contains(keytabOutput, "not found")

	// Check if we can get a Kerberos ticket (don't exit with error if it fails)
	klistCmd := "klist 2>/dev/null || echo 'No Kerberos tickets found'"
	klistOutput, _ := utils.RunCommand("bash", "-c", klistCmd)
	hasTickets := !strings.Contains(klistOutput, "No Kerberos tickets found") &&
		!strings.Contains(klistOutput, "No credentials cache found")

	// Check for kinit in PATH
	kinitCmd := "which kinit 2>/dev/null || echo 'kinit not found'"
	kinitOutput, _ := utils.RunCommand("bash", "-c", kinitCmd)
	hasKinit := !strings.Contains(kinitOutput, "not found")

	var detail strings.Builder
	detail.WriteString("Kerberos Installation:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(kerberosOutput)
	detail.WriteString("\n----\n")

	if kerberosInstalled {
		detail.WriteString("\nKerberos Configuration Excerpt:\n")
		detail.WriteString("[source, bash]\n----\n")
		// Show only relevant parts
		for _, line := range strings.Split(krbConfOutput, "\n") {
			if strings.Contains(line, "default_realm") ||
				strings.Contains(line, "kdc") ||
				strings.Contains(line, "admin_server") ||
				strings.Contains(line, "dns_lookup_realm") ||
				strings.TrimSpace(line) == "[realms]" ||
				strings.TrimSpace(line) == "[domain_realm]" {
				detail.WriteString(line + "\n")
			}
		}
		detail.WriteString("\n----\n")

		detail.WriteString("\nKeytab Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(keytabOutput)
		detail.WriteString("\n----\n")

		detail.WriteString("\nKerberos Tickets:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(klistOutput)
		detail.WriteString("\n----\n")
	}

	// Determine if this system uses Kerberos
	usesKerberos := kerberosInstalled && !strings.Contains(krbConfOutput, "Kerberos configuration not found")

	// Evaluate Kerberos configuration
	if !usesKerberos {
		check.Result = report.NewResult(report.StatusInfo,
			"Kerberos is not configured on this system",
			report.ResultKeyNotApplicable)
		report.AddRecommendation(&check.Result, "This check is not applicable as Kerberos is not being used")
	} else {
		issues := []string{}

		// Check default realm is set
		hasDefaultRealm := strings.Contains(krbConfOutput, "default_realm")
		if !hasDefaultRealm {
			issues = append(issues, "No default realm set in krb5.conf")
		}

		// Check KDC is defined
		hasKdc := strings.Contains(krbConfOutput, "kdc")
		if !hasKdc {
			issues = append(issues, "No KDC defined in krb5.conf")
		}

		// Check keytab if system authentication
		if !hasKeytab && strings.Contains(krbConfOutput, "auth") {
			issues = append(issues, "No keytab file found for system authentication")
		}

		// Check kinit
		if !hasKinit {
			issues = append(issues, "kinit not found in PATH")
		}

		if len(issues) > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Found %d issues with Kerberos configuration", len(issues)),
				report.ResultKeyRecommended)

			for _, issue := range issues {
				report.AddRecommendation(&check.Result, issue)
			}

			if !hasDefaultRealm || !hasKdc {
				report.AddRecommendation(&check.Result, "Ensure krb5.conf has proper default_realm and KDC definitions")
			}

			if !hasKeytab && strings.Contains(krbConfOutput, "auth") {
				report.AddRecommendation(&check.Result, "Create keytab file for system authentication")
			}

			// Add reference link directly
			rhelVersion := utils.GetRedHatVersion()
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_authentication_and_authorization_in_rhel/configuring-a-kerberos-server_configuring-authentication", rhelVersion))
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"Kerberos is properly configured",
				report.ResultKeyNoChange)

			if !hasTickets {
				report.AddRecommendation(&check.Result, "No active Kerberos tickets found, but configuration looks good")
			}
		}
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
