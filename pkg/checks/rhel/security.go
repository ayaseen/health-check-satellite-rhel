// pkg/checks/rhel/security.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunSecurityChecks performs security related checks
func RunSecurityChecks(r *report.AsciiDocReport) {
	// Check SELinux status
	checkSELinux(r)

	// Check auditd configuration
	checkAuditd(r)

	// Check password policy
	checkPasswordPolicy(r)

	// Check file permissions
	checkFilePermissions(r)

	// Check SSH hardening and PAM settings
	checkSSHHardening(r)

	// New: Check root account security
	checkRootSecurity(r)

	// New: Check shell history configuration
	checkShellHistory(r)
}

// checkSELinux ensures SELinux is enabled and enforcing
func checkSELinux(r *report.AsciiDocReport) {
	checkID := "security-selinux"
	checkName := "SELinux Status"
	checkDesc := "Ensures SELinux is enabled and enforcing."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Get SELinux status
	sestatusCmd := "sestatus"
	sestatusOutput, err := utils.RunCommand("bash", "-c", sestatusCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine SELinux status", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'sestatus' command is available.")
		report.AddRecommendation(&check.Result, "Install SELinux utilities with 'yum install policycoreutils'")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/using_selinux/", rhelVersion))
		r.AddCheck(check)
		return
	}

	// Get getenforce output
	getenforceCmd := "getenforce"
	getenforceOutput, _ := utils.RunCommand("bash", "-c", getenforceCmd)
	selinuxMode := strings.TrimSpace(getenforceOutput)

	// Check config file
	configCmd := "grep -E 'SELINUX=' /etc/selinux/config"
	configOutput, _ := utils.RunCommand("bash", "-c", configCmd)

	// Check for denials in audit log
	avcDenialsCmd := "grep -i 'avc.*denied' /var/log/audit/audit.log 2>/dev/null | wc -l || echo '0'"
	avcDenialsOutput, _ := utils.RunCommand("bash", "-c", avcDenialsCmd)
	avcDenialsCount := strings.TrimSpace(avcDenialsOutput)

	var detail strings.Builder
	detail.WriteString("SELinux Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sestatusOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("SELinux Mode:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(selinuxMode)
	detail.WriteString("\n----\n\n")

	detail.WriteString("SELinux Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(configOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("AVC Denials Count:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(avcDenialsCount)
	detail.WriteString("\n----\n")

	// Check if SELinux is disabled or permissive
	isEnforcing := strings.Contains(sestatusOutput, "enforcing") || selinuxMode == "Enforcing"
	isDisabled := strings.Contains(sestatusOutput, "disabled") || selinuxMode == "Disabled"
	isPermissive := strings.Contains(sestatusOutput, "permissive") || selinuxMode == "Permissive"

	// Check if config file has SELinux set to enforcing
	configEnforcing := strings.Contains(configOutput, "SELINUX=enforcing")

	// Process AVC denial count
	denialCount := 0
	fmt.Sscanf(avcDenialsCount, "%d", &denialCount)

	// Evaluate SELinux status
	if isDisabled {
		check.Result = report.NewResult(report.StatusCritical,
			"SELinux is disabled",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Enable SELinux by setting SELINUX=enforcing in /etc/selinux/config")
		report.AddRecommendation(&check.Result, "Reboot the system to activate SELinux")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/using_selinux/changing-selinux-states-and-modes_using-selinux", rhelVersion))
	} else if isPermissive {
		check.Result = report.NewResult(report.StatusWarning,
			"SELinux is in permissive mode",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set SELinux to enforcing mode with 'setenforce 1'")
		report.AddRecommendation(&check.Result, "Ensure SELINUX=enforcing in /etc/selinux/config for persistence")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/using_selinux/changing-selinux-states-and-modes_using-selinux", rhelVersion))
	} else if isEnforcing && !configEnforcing {
		check.Result = report.NewResult(report.StatusWarning,
			"SELinux is enforcing but not set in config file",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set SELINUX=enforcing in /etc/selinux/config for persistence")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/using_selinux/changing-selinux-states-and-modes_using-selinux", rhelVersion))
	} else if denialCount > 100 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("SELinux is enforcing but has %d AVC denials", denialCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review AVC denials in /var/log/audit/audit.log")
		report.AddRecommendation(&check.Result, "Use 'audit2allow' to generate policies for legitimate denials")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/using_selinux/troubleshooting-problems-related-to-selinux_using-selinux", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"SELinux is properly configured and enforcing",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkAuditd validates auditd configuration and log retention
func checkAuditd(r *report.AsciiDocReport) {
	checkID := "security-auditd"
	checkName := "Audit Configuration"
	checkDesc := "Validates auditd configuration and log retention."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)
	// Check if auditd is installed and running
	auditdServiceCmd := "systemctl is-active auditd"
	auditdServiceOutput, _ := utils.RunCommand("bash", "-c", auditdServiceCmd)
	auditdActive := strings.TrimSpace(auditdServiceOutput) == "active"

	// Get auditd configuration
	auditdConfigCmd := "cat /etc/audit/auditd.conf 2>/dev/null || echo 'Config file not found'"
	auditdConfigOutput, _ := utils.RunCommand("bash", "-c", auditdConfigCmd)

	// Check audit rules
	auditRulesCmd := "auditctl -l 2>/dev/null || echo 'No rules loaded'"
	auditRulesOutput, _ := utils.RunCommand("bash", "-c", auditRulesCmd)

	// Check log file size
	logSizeCmd := "ls -lh /var/log/audit/audit.log 2>/dev/null || echo 'Log file not found'"
	logSizeOutput, _ := utils.RunCommand("bash", "-c", logSizeCmd)

	// Check if TTY auditing is enabled for root
	ttyAuditCmd := "grep 'pam_tty_audit.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || echo 'TTY auditing not configured'"
	ttyAuditOutput, _ := utils.RunCommand("bash", "-c", ttyAuditCmd)

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("Auditd Service Active: %v\n\n", auditdActive))

	detail.WriteString("Audit Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	// Only show interesting parts of config
	for _, line := range strings.Split(auditdConfigOutput, "\n") {
		if strings.Contains(line, "max_log_file") ||
			strings.Contains(line, "num_logs") ||
			strings.Contains(line, "space_left") ||
			strings.Contains(line, "action") {
			detail.WriteString(line + "\n")
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Audit Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(auditRulesOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Audit Log File:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logSizeOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("TTY Auditing Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(ttyAuditOutput, "TTY auditing not configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(ttyAuditOutput)
	}
	detail.WriteString("\n----\n")

	// Check key requirements
	hasMaxLogSize := false
	hasNumLogs := false
	hasSpaceLeft := false
	hasSpaceAction := false
	maxLogSize := 0
	numLogs := 0

	for _, line := range strings.Split(auditdConfigOutput, "\n") {
		if strings.Contains(line, "max_log_file =") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &maxLogSize)
				hasMaxLogSize = true
			}
		} else if strings.Contains(line, "num_logs =") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &numLogs)
				hasNumLogs = true
			}
		} else if strings.Contains(line, "space_left =") {
			hasSpaceLeft = true
		} else if strings.Contains(line, "space_left_action =") ||
			strings.Contains(line, "admin_space_left_action =") {
			hasSpaceAction = true
		}
	}

	// Count number of rules
	ruleCount := 0
	for _, line := range strings.Split(auditRulesOutput, "\n") {
		if strings.HasPrefix(line, "-") {
			ruleCount++
		}
	}

	// Check for TTY auditing of root user
	hasTtyAudit := strings.Contains(ttyAuditOutput, "enable=root") ||
		strings.Contains(ttyAuditOutput, "enable=*") ||
		strings.Contains(ttyAuditOutput, "enable=root,")

	// Evaluate auditd configuration
	issues := []string{}

	if !auditdActive {
		issues = append(issues, "Audit daemon (auditd) is not active")
	}

	if ruleCount < 10 {
		issues = append(issues, fmt.Sprintf("Few audit rules defined (%d rules)", ruleCount))
	}

	if !hasMaxLogSize || maxLogSize < 8 {
		issues = append(issues, "max_log_file setting not configured properly")
	}

	if !hasNumLogs || numLogs < 5 {
		issues = append(issues, "num_logs setting not configured properly")
	}

	if !hasSpaceLeft {
		issues = append(issues, "space_left setting not found")
	}

	if !hasSpaceAction {
		issues = append(issues, "space_left_action setting not found")
	}

	if !hasTtyAudit {
		issues = append(issues, "TTY auditing not configured for root user")
	}

	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d issues with audit configuration", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !auditdActive {
			report.AddRecommendation(&check.Result, "Install and enable auditd: 'yum install audit && systemctl enable --now auditd'")
		}

		if ruleCount < 10 {
			report.AddRecommendation(&check.Result, "Configure audit rules in /etc/audit/rules.d/")
			report.AddRecommendation(&check.Result, "Follow security guidelines for critical events to audit")
		}

		if !hasMaxLogSize || maxLogSize < 8 {
			report.AddRecommendation(&check.Result, "Set max_log_file to at least 8 (MB) in /etc/audit/auditd.conf")
		}

		if !hasNumLogs || numLogs < 5 {
			report.AddRecommendation(&check.Result, "Set num_logs to at least 5 in /etc/audit/auditd.conf")
		}

		if !hasSpaceLeft {
			report.AddRecommendation(&check.Result, "Configure space_left in /etc/audit/auditd.conf")
		}

		if !hasSpaceAction {
			report.AddRecommendation(&check.Result, "Configure space_left_action in /etc/audit/auditd.conf")
		}

		if !hasTtyAudit {
			report.AddRecommendation(&check.Result, "Enable TTY auditing for root in /etc/pam.d/system-auth and password-auth: 'session required pam_tty_audit.so enable=root'")
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/configuring-auditd_security-hardening", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Audit daemon is active with %d rules configured", ruleCount),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPasswordPolicy confirms password policy and sudo access compliance
func checkPasswordPolicy(r *report.AsciiDocReport) {
	checkID := "security-password-policy"
	checkName := "Password Policy"
	checkDesc := "Confirms password policy and sudo access compliance."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check password policy (PAM)
	pamPwqualityCmd := "cat /etc/security/pwquality.conf 2>/dev/null || echo 'File not found'"
	pamPwqualityOutput, _ := utils.RunCommand("bash", "-c", pamPwqualityCmd)

	// Check password aging/expiration
	loginDefsCmd := "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs"
	loginDefsOutput, _ := utils.RunCommand("bash", "-c", loginDefsCmd)

	// Check failed login lockout
	pam_faillock_cmd := "grep -E 'pam_faillock.so' /etc/pam.d/password-auth 2>/dev/null || echo 'Not configured'"
	pam_faillock_output, _ := utils.RunCommand("bash", "-c", pam_faillock_cmd)

	// Check sudo access
	sudoersCmd := "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'No sudo rules found'"
	sudoersOutput, _ := utils.RunCommand("bash", "-c", sudoersCmd)

	// Check sudo log configuration
	sudoLogCmd := "grep -E 'Defaults.*log' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Sudo logging not configured'"
	sudoLogOutput, _ := utils.RunCommand("bash", "-c", sudoLogCmd)

	// Check for password hashing algorithm
	hashingAlgCmd := "grep -E '(sha512|md5|blowfish)' /etc/pam.d/system-auth || grep -E '(SHA|MD5)' /etc/login.defs"
	hashingAlgOutput, _ := utils.RunCommand("bash", "-c", hashingAlgCmd)

	var detail strings.Builder
	detail.WriteString("Password Quality Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pamPwqualityOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Password Aging Policy:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(loginDefsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Account Lockout Policy:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pam_faillock_output)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Sudo Access Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sudoersOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Sudo Logging Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sudoLogOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Password Hashing Algorithm:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hashingAlgOutput)
	detail.WriteString("\n----\n")

	// Check password complexity requirements
	minLen := 0
	hasDigits := false
	hasLowercase := false
	hasUppercase := false
	hasSpecial := false

	for _, line := range strings.Split(pamPwqualityOutput, "\n") {
		if strings.Contains(line, "minlen") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &minLen)
			}
		} else if strings.Contains(line, "dcredit") {
			hasDigits = true
		} else if strings.Contains(line, "lcredit") {
			hasLowercase = true
		} else if strings.Contains(line, "ucredit") {
			hasUppercase = true
		} else if strings.Contains(line, "ocredit") {
			hasSpecial = true
		}
	}

	// Check password aging
	maxDays := 99999
	minDays := 0
	warnAge := 0

	for _, line := range strings.Split(loginDefsOutput, "\n") {
		if strings.Contains(line, "PASS_MAX_DAYS") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &maxDays)
			}
		} else if strings.Contains(line, "PASS_MIN_DAYS") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &minDays)
			}
		} else if strings.Contains(line, "PASS_WARN_AGE") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				fmt.Sscanf(parts[1], "%d", &warnAge)
			}
		}
	}

	// Check account lockout
	hasLockout := !strings.Contains(pam_faillock_output, "Not configured")

	// Check sudo logging
	hasSudoLogging := !strings.Contains(sudoLogOutput, "not configured")

	// Check for secure hashing
	hasSecureHashing := strings.Contains(hashingAlgOutput, "sha512") && !strings.Contains(hashingAlgOutput, "md5")

	// Evaluate password policy compliance
	policyIssues := []string{}

	if minLen < 8 {
		policyIssues = append(policyIssues, "Password minimum length should be at least 8 characters")
	}

	if !hasDigits || !hasLowercase || !hasUppercase || !hasSpecial {
		policyIssues = append(policyIssues, "Password complexity requirements incomplete")
	}

	if maxDays > 90 {
		policyIssues = append(policyIssues, fmt.Sprintf("Password maximum age (%d days) exceeds 90 days", maxDays))
	}

	if !hasLockout {
		policyIssues = append(policyIssues, "Account lockout policy not configured")
	}

	if !hasSudoLogging {
		policyIssues = append(policyIssues, "Sudo command logging not configured")
	}

	if !hasSecureHashing {
		policyIssues = append(policyIssues, "Secure password hashing (SHA-512) not configured")
	}

	if len(policyIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d password policy issues", len(policyIssues)),
			report.ResultKeyRecommended)

		for _, issue := range policyIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if minLen < 8 {
			report.AddRecommendation(&check.Result, "Set minlen=8 in /etc/security/pwquality.conf")
		}

		if !hasLockout {
			report.AddRecommendation(&check.Result, "Configure pam_faillock.so in /etc/pam.d/system-auth and /etc/pam.d/password-auth")
		}

		if !hasSudoLogging {
			report.AddRecommendation(&check.Result, "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers")
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/using-tools-and-services-to-enhance-security_security-hardening#configuring-password-security_using-tools-and-services-to-enhance-security", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Password policy and sudo access controls are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFilePermissions checks permissions on sensitive files and directories
func checkFilePermissions(r *report.AsciiDocReport) {
	checkID := "security-file-permissions"
	checkName := "File Permissions"
	checkDesc := "Checks permissions on sensitive files and directories."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Define sensitive files to check
	sensitiveFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
		"/etc/ssh/sshd_config",
		"/etc/sudoers",
		"/etc/crontab",
		"/var/log/wtmp",
		"/var/log/btmp",
		"/var/log/lastlog",
	}

	// Check permissions on sensitive files
	var detail strings.Builder
	detail.WriteString("File Permissions for Sensitive Files:\n")
	detail.WriteString("[source, bash]\n----\n")

	// Create command to check all sensitive files
	permCheckCmd := "ls -l " + strings.Join(sensitiveFiles, " ") + " 2>/dev/null || echo 'File not found'"
	permCheckOutput, _ := utils.RunCommand("bash", "-c", permCheckCmd)
	detail.WriteString(permCheckOutput)
	detail.WriteString("\n----\n\n")

	// Check world-writable files in important directories
	worldWritableCmd := "find /etc /var/log /opt /usr/bin /usr/sbin -type f -perm -0002 -ls 2>/dev/null | head -20"
	worldWritableOutput, _ := utils.RunCommand("bash", "-c", worldWritableCmd)

	if strings.TrimSpace(worldWritableOutput) != "" {
		detail.WriteString("World-Writable Files Found:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(worldWritableOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No world-writable files found in key directories.\n\n")
	}

	// Check world-readable log files (new)
	worldReadableLogsCmd := "find /var/log -type f -perm -0004 -ls 2>/dev/null | head -20"
	worldReadableLogsOutput, _ := utils.RunCommand("bash", "-c", worldReadableLogsCmd)

	if strings.TrimSpace(worldReadableLogsOutput) != "" {
		detail.WriteString("World-Readable Log Files Found:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(worldReadableLogsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No world-readable log files found.\n\n")
	}

	// Check cron directory permissions (new)
	cronDirPermCmd := "ls -ld /etc/cron.d 2>/dev/null || echo 'Directory not found'"
	cronDirPermOutput, _ := utils.RunCommand("bash", "-c", cronDirPermCmd)

	detail.WriteString("Cron Directory Permissions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cronDirPermOutput)
	detail.WriteString("\n----\n\n")

	// Check for immutable files (new)
	immutableFilesCmd := "lsattr /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/hosts 2>/dev/null | grep -- '----i' || echo 'No immutable flags found'"
	immutableFilesOutput, _ := utils.RunCommand("bash", "-c", immutableFilesCmd)

	detail.WriteString("Immutable Critical Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(immutableFilesOutput)
	detail.WriteString("\n----\n\n")

	// Check SELinux file contexts for sensitive files (new)
	selinuxContextsCmd := "ls -Z /etc/passwd /etc/shadow /etc/ssh/sshd_config 2>/dev/null || echo 'SELinux contexts not available'"
	selinuxContextsOutput, _ := utils.RunCommand("bash", "-c", selinuxContextsCmd)

	detail.WriteString("SELinux Contexts for Critical Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(selinuxContextsOutput)
	detail.WriteString("\n----\n\n")

	// Check audit rules for critical files (new)
	auditRulesCmd := "grep -E '/etc/(passwd|shadow|group|gshadow)' /etc/audit/rules.d/*.rules 2>/dev/null || echo 'No audit rules found for critical files'"
	auditRulesOutput, _ := utils.RunCommand("bash", "-c", auditRulesCmd)

	detail.WriteString("Audit Rules for Critical Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(auditRulesOutput)
	detail.WriteString("\n----\n\n")

	// Check SCAP Security Guide installation (new)
	scapInstallCmd := "rpm -q scap-security-guide openscap-scanner 2>/dev/null || echo 'SCAP packages not installed'"
	scapInstallOutput, _ := utils.RunCommand("bash", "-c", scapInstallCmd)

	detail.WriteString("SCAP Security Tools Installation:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(scapInstallOutput)
	detail.WriteString("\n----\n\n")

	// Check for SUID/SGID binaries - using a whitelist approach
	// Define common approved SUID/SGID binaries based on Red Hat recommendations
	approvedSuidBinaries := []string{
		"mount", "umount", "sudo", "su", "passwd", "chage", "gpasswd",
		"newgrp", "chsh", "at", "pkexec", "policycoreutils", "unix_chkpwd",
		"ping", "ping6", "setarch", "ksu", "usernetctl", "traceroute",
		"userhelper", "postdrop", "postqueue", "ssh-agent", "crontab",
	}

	// Build a regex pattern for approved binaries
	approvedBinariesPattern := strings.Join(approvedSuidBinaries, "|")

	// Find SUID/SGID binaries not in the approved list
	suidBinariesCmd := fmt.Sprintf("find /usr/bin /usr/sbin /bin /sbin -perm /6000 -type f | grep -v -E '(%s)' | sort | head -30", approvedBinariesPattern)
	suidBinariesOutput, _ := utils.RunCommand("bash", "-c", suidBinariesCmd)

	if strings.TrimSpace(suidBinariesOutput) != "" {
		detail.WriteString("Unapproved SUID/SGID Binaries Found (whitelist approach):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(suidBinariesOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No unapproved SUID/SGID binaries found.\n")
	}

	// Check for file permission issues
	permissionIssues := []string{}

	// Check world-readable shadow file
	if strings.Contains(permCheckOutput, "/etc/shadow -rw-r--r--") ||
		strings.Contains(permCheckOutput, "/etc/shadow -rw-rw-r--") {
		permissionIssues = append(permissionIssues, "/etc/shadow is world-readable")
	}

	// Check world-writable password file
	if strings.Contains(permCheckOutput, "/etc/passwd -rw-rw-rw-") ||
		strings.Contains(permCheckOutput, "/etc/passwd -rw-r--rw-") {
		permissionIssues = append(permissionIssues, "/etc/passwd is world-writable")
	}

	// Check SSH config permissions
	if strings.Contains(permCheckOutput, "/etc/ssh/sshd_config -rw-r--r--") ||
		strings.Contains(permCheckOutput, "/etc/ssh/sshd_config -rw-rw-r--") ||
		strings.Contains(permCheckOutput, "/etc/ssh/sshd_config -rw-rw-rw-") {
		permissionIssues = append(permissionIssues, "/etc/ssh/sshd_config has overly permissive permissions")
	}

	// Check if world-writable files were found
	hasWorldWritable := strings.TrimSpace(worldWritableOutput) != ""
	if hasWorldWritable {
		permissionIssues = append(permissionIssues, "World-writable files found in key directories")
	}

	// Check if world-readable log files were found (new)
	hasWorldReadableLogs := strings.TrimSpace(worldReadableLogsOutput) != ""
	if hasWorldReadableLogs {
		permissionIssues = append(permissionIssues, "World-readable log files found in /var/log")
	}

	// Check cron.d directory permissions (new)
	cronDirCorrectPerms := strings.Contains(cronDirPermOutput, "drwx------") || strings.Contains(cronDirPermOutput, "700")
	if !cronDirCorrectPerms && !strings.Contains(cronDirPermOutput, "Directory not found") {
		permissionIssues = append(permissionIssues, "/etc/cron.d directory has incorrect permissions (should be 700)")
	}

	// Check for immutable critical files (new)
	hasImmutableFiles := !strings.Contains(immutableFilesOutput, "No immutable flags found")
	if !hasImmutableFiles {
		permissionIssues = append(permissionIssues, "Critical configuration files are not set as immutable")
	}

	// Check SELinux contexts (new)
	hasShadowContext := strings.Contains(selinuxContextsOutput, "shadow_t")
	if !hasShadowContext && !strings.Contains(selinuxContextsOutput, "SELinux contexts not available") {
		permissionIssues = append(permissionIssues, "SELinux contexts may not be properly set for critical files")
	}

	// Check audit rules (new)
	hasAuditRules := !strings.Contains(auditRulesOutput, "No audit rules found")
	if !hasAuditRules {
		permissionIssues = append(permissionIssues, "No audit rules configured for critical files")
	}

	// Check SCAP Security Guide installation (new)
	hasScapTools := !strings.Contains(scapInstallOutput, "not installed")
	if !hasScapTools {
		permissionIssues = append(permissionIssues, "SCAP Security Guide tools not installed for automated compliance scanning")
	}

	// Check if unusual SUID binaries were found
	hasUnapprovedSuid := strings.TrimSpace(suidBinariesOutput) != ""
	if hasUnapprovedSuid {
		permissionIssues = append(permissionIssues, "Unapproved SUID/SGID binaries found (not in whitelist)")
	}

	// Evaluate file permissions
	if len(permissionIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d file permission issues", len(permissionIssues)),
			report.ResultKeyRecommended)

		for _, issue := range permissionIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if strings.Contains(permCheckOutput, "/etc/shadow -rw-r--r--") ||
			strings.Contains(permCheckOutput, "/etc/shadow -rw-rw-r--") {
			report.AddRecommendation(&check.Result, "Fix /etc/shadow permissions: 'chmod 0400 /etc/shadow'")
		}

		if strings.Contains(permCheckOutput, "/etc/ssh/sshd_config -rw-r--r--") ||
			strings.Contains(permCheckOutput, "/etc/ssh/sshd_config -rw-rw-r--") {
			report.AddRecommendation(&check.Result, "Fix /etc/ssh/sshd_config permissions: 'chmod 0600 /etc/ssh/sshd_config'")
		}

		if hasWorldWritable {
			report.AddRecommendation(&check.Result, "Remove world-writable permissions from files: 'chmod o-w <file>'")
		}

		if hasWorldReadableLogs {
			report.AddRecommendation(&check.Result, "Remove world-readable permissions from log files: 'chmod o-r /var/log/*'")
		}

		if !cronDirCorrectPerms && !strings.Contains(cronDirPermOutput, "Directory not found") {
			report.AddRecommendation(&check.Result, "Fix /etc/cron.d directory permissions: 'chmod 700 /etc/cron.d'")
		}

		if !hasImmutableFiles {
			report.AddRecommendation(&check.Result, "Consider setting critical files as immutable: 'chattr +i /etc/passwd /etc/shadow'")
		}

		if !hasShadowContext && !strings.Contains(selinuxContextsOutput, "SELinux contexts not available") {
			report.AddRecommendation(&check.Result, "Restore proper SELinux contexts: 'restorecon -v /etc/passwd /etc/shadow /etc/ssh/sshd_config'")
		}

		if !hasAuditRules {
			report.AddRecommendation(&check.Result, "Configure audit rules for critical files: 'echo \"-w /etc/passwd -p wa -k identity\" >> /etc/audit/rules.d/audit.rules'")
		}

		if !hasScapTools {
			report.AddRecommendation(&check.Result, "Install SCAP Security Guide: 'yum install scap-security-guide openscap-scanner'")
		}

		if hasUnapprovedSuid {
			report.AddRecommendation(&check.Result, "Review and remove SUID/SGID from unapproved binaries: 'chmod -s <file>'")
			report.AddRecommendation(&check.Result, "Maintain a whitelist of allowed SUID/SGID binaries per Red Hat recommendations")
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/assembly_securing-files-and-directories_security-hardening", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"File permissions on sensitive files appear to be correct",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSSHHardening reviews SSH hardening and PAM settings
func checkSSHHardening(r *report.AsciiDocReport) {
	checkID := "security-ssh-hardening"
	checkName := "SSH Hardening"
	checkDesc := "Reviews SSH hardening and PAM settings."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check SSH config - we'll use it, keeping the variable
	sshConfigCmd := "cat /etc/ssh/sshd_config 2>/dev/null || echo 'File not found'"
	sshConfigOutput, _ := utils.RunCommand("bash", "-c", sshConfigCmd)

	// Check key SSH settings
	protocolCmd := "grep -E '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'Protocol setting not found'"
	protocolOutput, _ := utils.RunCommand("bash", "-c", protocolCmd)

	rootLoginCmd := "grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin setting not found'"
	rootLoginOutput, _ := utils.RunCommand("bash", "-c", rootLoginCmd)

	emptyPasswdCmd := "grep -E '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitEmptyPasswords setting not found'"
	emptyPasswdOutput, _ := utils.RunCommand("bash", "-c", emptyPasswdCmd)

	x11ForwardingCmd := "grep -E '^X11Forwarding' /etc/ssh/sshd_config 2>/dev/null || echo 'X11Forwarding setting not found'"
	x11ForwardingOutput, _ := utils.RunCommand("bash", "-c", x11ForwardingCmd)

	maxAuthTriesCmd := "grep -E '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || echo 'MaxAuthTries setting not found'"
	maxAuthTriesOutput, _ := utils.RunCommand("bash", "-c", maxAuthTriesCmd)

	// New checks for additional SSH hardening settings
	passwordAuthCmd := "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'PasswordAuthentication setting not found'"
	passwordAuthOutput, _ := utils.RunCommand("bash", "-c", passwordAuthCmd)

	challengeAuthCmd := "grep -E '^ChallengeResponseAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'ChallengeResponseAuthentication setting not found'"
	challengeAuthOutput, _ := utils.RunCommand("bash", "-c", challengeAuthCmd)

	loginGraceTimeCmd := "grep -E '^LoginGraceTime' /etc/ssh/sshd_config 2>/dev/null || echo 'LoginGraceTime setting not found'"
	loginGraceTimeOutput, _ := utils.RunCommand("bash", "-c", loginGraceTimeCmd)

	clientAliveIntervalCmd := "grep -E '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null || echo 'ClientAliveInterval setting not found'"
	clientAliveIntervalOutput, _ := utils.RunCommand("bash", "-c", clientAliveIntervalCmd)

	clientAliveCountMaxCmd := "grep -E '^ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null || echo 'ClientAliveCountMax setting not found'"
	clientAliveCountMaxOutput, _ := utils.RunCommand("bash", "-c", clientAliveCountMaxCmd)

	hostbasedAuthCmd := "grep -E '^HostbasedAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'HostbasedAuthentication setting not found'"
	hostbasedAuthOutput, _ := utils.RunCommand("bash", "-c", hostbasedAuthCmd)

	tcpForwardingCmd := "grep -E '^AllowTcpForwarding' /etc/ssh/sshd_config 2>/dev/null || echo 'AllowTcpForwarding setting not found'"
	tcpForwardingOutput, _ := utils.RunCommand("bash", "-c", tcpForwardingCmd)

	bannerCmd := "grep -E '^Banner' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' || echo 'Banner setting not found or commented out'"
	bannerOutput, _ := utils.RunCommand("bash", "-c", bannerCmd)

	allowUsersCmd := "grep -E '^(AllowUsers|AllowGroups)' /etc/ssh/sshd_config 2>/dev/null || echo 'AllowUsers/AllowGroups settings not found'"
	allowUsersOutput, _ := utils.RunCommand("bash", "-c", allowUsersCmd)

	ciphersCmd := "grep -E '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'Ciphers setting not found'"
	ciphersOutput, _ := utils.RunCommand("bash", "-c", ciphersCmd)

	macsCmd := "grep -E '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo 'MACs setting not found'"
	macsOutput, _ := utils.RunCommand("bash", "-c", macsCmd)

	kexAlgorithmsCmd := "grep -E '^KexAlgorithms' /etc/ssh/sshd_config 2>/dev/null || echo 'KexAlgorithms setting not found'"
	kexAlgorithmsOutput, _ := utils.RunCommand("bash", "-c", kexAlgorithmsCmd)

	useDNSCmd := "grep -E '^UseDNS' /etc/ssh/sshd_config 2>/dev/null || echo 'UseDNS setting not found'"
	useDNSOutput, _ := utils.RunCommand("bash", "-c", useDNSCmd)

	// Check SSH config file permissions
	sshConfigPermCmd := "stat -c '%a %U:%G' /etc/ssh/sshd_config 2>/dev/null || echo 'Unable to check permissions'"
	sshConfigPermOutput, _ := utils.RunCommand("bash", "-c", sshConfigPermCmd)

	// Check SSH host key file permissions
	hostKeyPermCmd := "find /etc/ssh/ -name 'ssh_host_*_key' -exec stat -c '%n %a %U:%G' {} \\; 2>/dev/null || echo 'Unable to check host key permissions'"
	hostKeyPermOutput, _ := utils.RunCommand("bash", "-c", hostKeyPermCmd)

	// Check PAM settings
	pamSshCmd := "cat /etc/pam.d/sshd 2>/dev/null || echo 'File not found'"
	pamSshOutput, _ := utils.RunCommand("bash", "-c", pamSshCmd)

	var detail strings.Builder
	detail.WriteString("SSH Configuration File Content:\n")
	detail.WriteString("[source, bash]\n----\n")
	// Truncate the output if it's too long to avoid extremely large reports
	sshConfigLines := strings.Split(sshConfigOutput, "\n")
	if len(sshConfigLines) > 20 {
		// Show the first 20 lines with a message indicating truncation
		detail.WriteString(strings.Join(sshConfigLines[:20], "\n"))
		detail.WriteString("\n... (output truncated) ...\n")
	} else {
		detail.WriteString(sshConfigOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("SSH Server Configuration Highlights:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString("Protocol: " + protocolOutput + "\n")
	detail.WriteString("Root Login: " + rootLoginOutput + "\n")
	detail.WriteString("Empty Passwords: " + emptyPasswdOutput + "\n")
	detail.WriteString("X11 Forwarding: " + x11ForwardingOutput + "\n")
	detail.WriteString("Max Auth Tries: " + maxAuthTriesOutput + "\n")
	detail.WriteString("Password Authentication: " + passwordAuthOutput + "\n")
	detail.WriteString("Challenge Response Auth: " + challengeAuthOutput + "\n")
	detail.WriteString("Login Grace Time: " + loginGraceTimeOutput + "\n")
	detail.WriteString("Client Alive Interval: " + clientAliveIntervalOutput + "\n")
	detail.WriteString("Client Alive Count Max: " + clientAliveCountMaxOutput + "\n")
	detail.WriteString("Hostbased Authentication: " + hostbasedAuthOutput + "\n")
	detail.WriteString("TCP Forwarding: " + tcpForwardingOutput + "\n")
	detail.WriteString("Banner: " + bannerOutput + "\n")
	detail.WriteString("Allow Users/Groups: " + allowUsersOutput + "\n")
	detail.WriteString("UseDNS: " + useDNSOutput + "\n")
	detail.WriteString("Ciphers: " + ciphersOutput + "\n")
	detail.WriteString("MACs: " + macsOutput + "\n")
	detail.WriteString("Key Exchange Algorithms: " + kexAlgorithmsOutput + "\n")
	detail.WriteString("\n----\n\n")

	detail.WriteString("SSH Configuration File Permissions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString("sshd_config: " + sshConfigPermOutput + "\n")
	detail.WriteString("\n----\n\n")

	detail.WriteString("SSH Host Key File Permissions:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(hostKeyPermOutput, "Unable to check host key permissions") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(hostKeyPermOutput + "\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("PAM SSH Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(pamSshOutput, "File not found") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(pamSshOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check for SSH hardening issues
	hardeningIssues := []string{}

	// Check Protocol version
	if strings.Contains(protocolOutput, "Protocol 1") {
		hardeningIssues = append(hardeningIssues, "SSH Protocol 1 is enabled (insecure)")
	}

	// Check root login
	if strings.Contains(rootLoginOutput, "yes") {
		hardeningIssues = append(hardeningIssues, "SSH root login is allowed")
	}

	// Check empty passwords
	if strings.Contains(emptyPasswdOutput, "yes") {
		hardeningIssues = append(hardeningIssues, "SSH empty passwords are allowed")
	}

	// Check X11 forwarding
	if strings.Contains(x11ForwardingOutput, "yes") {
		hardeningIssues = append(hardeningIssues, "SSH X11 forwarding is enabled")
	}

	// Check max auth tries
	maxTries := 6 // Default value
	if strings.Contains(maxAuthTriesOutput, "MaxAuthTries") {
		parts := strings.Fields(maxAuthTriesOutput)
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &maxTries)
		}
	}

	if maxTries > 4 {
		hardeningIssues = append(hardeningIssues, fmt.Sprintf("SSH MaxAuthTries is set to %d (recommended max: 4)", maxTries))
	}

	// Check PasswordAuthentication
	if strings.Contains(passwordAuthOutput, "yes") {
		hardeningIssues = append(hardeningIssues, "Password authentication is enabled (key-based authentication is more secure)")
	}

	// Check ChallengeResponseAuthentication
	if strings.Contains(challengeAuthOutput, "yes") {
		hardeningIssues = append(hardeningIssues, "Challenge response authentication is enabled")
	}

	// Check LoginGraceTime
	loginGraceTime := 120 // Default value in seconds
	if strings.Contains(loginGraceTimeOutput, "LoginGraceTime") {
		parts := strings.Fields(loginGraceTimeOutput)
		if len(parts) > 1 {
			// Handle values with time units (s, m)
			timeValue := parts[1]
			if strings.HasSuffix(timeValue, "s") {
				fmt.Sscanf(timeValue[:len(timeValue)-1], "%d", &loginGraceTime)
			} else if strings.HasSuffix(timeValue, "m") {
				minutes := 0
				fmt.Sscanf(timeValue[:len(timeValue)-1], "%d", &minutes)
				loginGraceTime = minutes * 60
			} else {
				fmt.Sscanf(timeValue, "%d", &loginGraceTime)
			}
		}
	}

	if loginGraceTime > 60 || strings.Contains(loginGraceTimeOutput, "not found") {
		hardeningIssues = append(hardeningIssues, fmt.Sprintf("LoginGraceTime is %d seconds (recommended: 60s or less)", loginGraceTime))
	}

	// Check ClientAliveInterval
	clientAliveInterval := 0 // Default value
	if strings.Contains(clientAliveIntervalOutput, "ClientAliveInterval") {
		parts := strings.Fields(clientAliveIntervalOutput)
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &clientAliveInterval)
		}
	}

	if clientAliveInterval == 0 || clientAliveInterval > 300 {
		hardeningIssues = append(hardeningIssues, fmt.Sprintf("ClientAliveInterval is %d (recommended: 300s or less, but not 0)", clientAliveInterval))
	}

	// Check ClientAliveCountMax
	clientAliveCountMax := 3 // Default value
	if strings.Contains(clientAliveCountMaxOutput, "ClientAliveCountMax") {
		parts := strings.Fields(clientAliveCountMaxOutput)
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &clientAliveCountMax)
		}
	}

	if clientAliveCountMax > 3 {
		hardeningIssues = append(hardeningIssues, fmt.Sprintf("ClientAliveCountMax is %d (recommended: 3 or less)", clientAliveCountMax))
	}

	// Check HostbasedAuthentication
	if !strings.Contains(hostbasedAuthOutput, "no") {
		hardeningIssues = append(hardeningIssues, "HostbasedAuthentication is not explicitly disabled")
	}

	// Check AllowTcpForwarding
	if !strings.Contains(tcpForwardingOutput, "no") {
		hardeningIssues = append(hardeningIssues, "TCP forwarding is not explicitly disabled")
	}

	// Check Banner
	if strings.Contains(bannerOutput, "not found") || strings.Contains(bannerOutput, "commented out") {
		hardeningIssues = append(hardeningIssues, "No SSH banner configured")
	}

	// Check AllowUsers or AllowGroups
	if strings.Contains(allowUsersOutput, "not found") {
		hardeningIssues = append(hardeningIssues, "No AllowUsers or AllowGroups restrictions configured")
	}

	// Check UseDNS
	if !strings.Contains(useDNSOutput, "no") {
		hardeningIssues = append(hardeningIssues, "UseDNS is not set to 'no' (can cause connection delays)")
	}

	// Check Ciphers, MACs, and KexAlgorithms
	// This is simplified; in a real environment, you'd check against organization-specific policies
	if strings.Contains(ciphersOutput, "not found") {
		hardeningIssues = append(hardeningIssues, "No explicit Ciphers configured (using default list)")
	} else if strings.Contains(ciphersOutput, "3des") || strings.Contains(ciphersOutput, "blowfish") || strings.Contains(ciphersOutput, "arcfour") {
		hardeningIssues = append(hardeningIssues, "Weak ciphers found in configuration")
	}

	if strings.Contains(macsOutput, "not found") {
		hardeningIssues = append(hardeningIssues, "No explicit MACs configured (using default list)")
	} else if strings.Contains(macsOutput, "hmac-md5") || strings.Contains(macsOutput, "hmac-sha1") {
		hardeningIssues = append(hardeningIssues, "Weak MACs found in configuration")
	}

	if strings.Contains(kexAlgorithmsOutput, "not found") {
		hardeningIssues = append(hardeningIssues, "No explicit KexAlgorithms configured (using default list)")
	} else if strings.Contains(kexAlgorithmsOutput, "diffie-hellman-group1") || strings.Contains(kexAlgorithmsOutput, "diffie-hellman-group14-sha1") {
		hardeningIssues = append(hardeningIssues, "Weak key exchange algorithms found in configuration")
	}

	// Check SSH config file permissions
	if !strings.Contains(sshConfigPermOutput, "600 root:root") && !strings.Contains(sshConfigPermOutput, "644 root:root") {
		hardeningIssues = append(hardeningIssues, "SSH config file has incorrect permissions or ownership (should be 600 or 644, owned by root)")
	}

	// Check SSH host key file permissions
	if strings.Contains(hostKeyPermOutput, "Unable to check") {
		hardeningIssues = append(hardeningIssues, "Unable to check SSH host key file permissions")
	} else {
		// Look for any host key with incorrect permissions
		for _, line := range strings.Split(hostKeyPermOutput, "\n") {
			if line == "" || strings.Contains(line, "Unable to check") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 3 {
				perms := parts[1]
				owner := parts[2]

				// Private keys should be 600 or more restrictive, owned by root
				if !strings.HasPrefix(perms, "600") && !strings.HasPrefix(perms, "400") {
					hardeningIssues = append(hardeningIssues, fmt.Sprintf("SSH host key %s has incorrect permissions: %s (should be 600)", parts[0], perms))
				}

				if owner != "root:root" {
					hardeningIssues = append(hardeningIssues, fmt.Sprintf("SSH host key %s has incorrect ownership: %s (should be root:root)", parts[0], owner))
				}
			}
		}
	}

	// Check for PAM faillock configuration
	hasFaillock := strings.Contains(pamSshOutput, "pam_faillock.so")
	if !hasFaillock {
		hardeningIssues = append(hardeningIssues, "PAM faillock not configured for SSH (account lockout protection missing)")
	}

	// Check for PAM password quality configuration
	hasPwquality := strings.Contains(pamSshOutput, "pam_pwquality.so") || strings.Contains(pamSshOutput, "pam_cracklib.so")
	if !hasPwquality {
		hardeningIssues = append(hardeningIssues, "PAM password quality not configured for SSH (password complexity checks missing)")
	}

	// Evaluate SSH hardening
	if len(hardeningIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d SSH hardening issues", len(hardeningIssues)),
			report.ResultKeyRecommended)

		for _, issue := range hardeningIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Edit /etc/ssh/sshd_config and set recommended values:")
		report.AddRecommendation(&check.Result, "- Protocol 2")
		report.AddRecommendation(&check.Result, "- PermitRootLogin no")
		report.AddRecommendation(&check.Result, "- PermitEmptyPasswords no")
		report.AddRecommendation(&check.Result, "- X11Forwarding no")
		report.AddRecommendation(&check.Result, "- MaxAuthTries 4")
		report.AddRecommendation(&check.Result, "- PasswordAuthentication no (if key-based auth is set up)")
		report.AddRecommendation(&check.Result, "- ChallengeResponseAuthentication no")
		report.AddRecommendation(&check.Result, "- LoginGraceTime 60")
		report.AddRecommendation(&check.Result, "- ClientAliveInterval 300")
		report.AddRecommendation(&check.Result, "- ClientAliveCountMax 3")
		report.AddRecommendation(&check.Result, "- HostbasedAuthentication no")
		report.AddRecommendation(&check.Result, "- AllowTcpForwarding no")
		report.AddRecommendation(&check.Result, "- Banner /etc/issue.net")
		report.AddRecommendation(&check.Result, "- UseDNS no")
		report.AddRecommendation(&check.Result, "Configure AllowUsers or AllowGroups to restrict SSH access")
		report.AddRecommendation(&check.Result, "Ensure SSH configuration files have appropriate permissions (chmod 600 /etc/ssh/sshd_config)")
		report.AddRecommendation(&check.Result, "Restart SSH after changes: 'systemctl restart sshd'")

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/assembly_securing-the-openssh-service_security-hardening", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"SSH server appears to be properly hardened",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRootSecurity checks root account security and restrictions
func checkRootSecurity(r *report.AsciiDocReport) {
	checkID := "security-root-account"
	checkName := "Root Account Security"
	checkDesc := "Checks security and restrictions for the root account."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check root login shell
	rootShellCmd := "grep '^root:' /etc/passwd | awk -F: '{print $7}'"
	rootShellOutput, _ := utils.RunCommand("bash", "-c", rootShellCmd)
	rootShell := strings.TrimSpace(rootShellOutput)

	// Check /etc/securetty presence and content
	securettyCmd := "cat /etc/securetty 2>/dev/null || echo 'File not found'"
	securettyOutput, _ := utils.RunCommand("bash", "-c", securettyCmd)

	// Check for root access via console
	consoleRootCmd := "grep 'console' /etc/securetty 2>/dev/null || echo 'No console entry'"
	consoleRootOutput, _ := utils.RunCommand("bash", "-c", consoleRootCmd)

	// Check sudo configuration for wheel group
	sudoWheelCmd := "grep -E '^%wheel' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'No wheel group configuration found'"
	sudoWheelOutput, _ := utils.RunCommand("bash", "-c", sudoWheelCmd)

	// Check /etc/profile for root idle timeout
	rootTimeoutCmd := "grep -E 'TMOUT=|readonly TMOUT' /etc/profile /etc/profile.d/*.sh 2>/dev/null || echo 'No root timeout configured'"
	rootTimeoutOutput, _ := utils.RunCommand("bash", "-c", rootTimeoutCmd)

	// Check GRUB password protection
	grubPasswdCmd := "grep 'password' /boot/grub2/grub.cfg 2>/dev/null || echo 'No GRUB password found'"
	grubPasswdOutput, _ := utils.RunCommand("bash", "-c", grubPasswdCmd)

	// Check wheel group membership
	wheelMembersCmd := "getent group wheel | cut -d: -f4 || echo 'No wheel group members'"
	wheelMembersOutput, _ := utils.RunCommand("bash", "-c", wheelMembersCmd)

	// Check su audit records
	suAuditCmd := "grep 'pam_tty_audit.so' /etc/pam.d/su 2>/dev/null || echo 'No TTY auditing for su configured'"
	suAuditOutput, _ := utils.RunCommand("bash", "-c", suAuditCmd)

	var detail strings.Builder
	detail.WriteString("Root Account Security Analysis:\n\n")

	detail.WriteString("Root Login Shell:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rootShell + "\n")
	detail.WriteString("\n----\n\n")

	detail.WriteString("Securetty Configuration (terminals allowed for root login):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(securettyOutput, "File not found") {
		detail.WriteString("None\n")
	} else {
		lines := strings.Split(securettyOutput, "\n")
		if len(lines) > 20 {
			// Show truncated output if too long
			detail.WriteString(strings.Join(lines[:20], "\n"))
			detail.WriteString("\n... (truncated) ...\n")
		} else {
			detail.WriteString(securettyOutput)
		}
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Wheel Group Configuration in Sudoers:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(sudoWheelOutput, "No wheel group configuration found") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(sudoWheelOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Root Idle Timeout Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(rootTimeoutOutput, "No root timeout configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(rootTimeoutOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("GRUB Password Protection:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(grubPasswdOutput, "No GRUB password found") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString("GRUB password configured\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Members of Wheel Group:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(wheelMembersOutput, "No wheel group members") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(wheelMembersOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("TTY Auditing for SU Command:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(suAuditOutput, "No TTY auditing for su configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(suAuditOutput)
	}
	detail.WriteString("\n----\n")

	// Check for issues
	rootSecurityIssues := []string{}

	// Is root shell set to a valid login shell?
	isRootLoginAllowed := (rootShell != "/sbin/nologin" && rootShell != "/usr/sbin/nologin" &&
		rootShell != "/bin/false" && rootShell != "/usr/bin/false")
	if isRootLoginAllowed {
		rootSecurityIssues = append(rootSecurityIssues, "Root account has a valid login shell")
	}

	// Is securetty limiting root console access?
	isSecurettyEmpty := (strings.Contains(securettyOutput, "File not found") ||
		strings.TrimSpace(securettyOutput) == "")
	if !isSecurettyEmpty && strings.Contains(consoleRootOutput, "console") {
		rootSecurityIssues = append(rootSecurityIssues, "Root console login is allowed in /etc/securetty")
	}

	// Is wheel group properly configured in sudoers?
	hasWheelConfig := !strings.Contains(sudoWheelOutput, "No wheel group configuration found")
	if !hasWheelConfig {
		rootSecurityIssues = append(rootSecurityIssues, "Wheel group not properly configured in sudoers")
	}

	// Is root idle timeout configured?
	hasRootTimeout := !strings.Contains(rootTimeoutOutput, "No root timeout configured")
	if !hasRootTimeout {
		rootSecurityIssues = append(rootSecurityIssues, "No root idle timeout configured")
	}

	// Is GRUB password protected?
	hasGrubPassword := !strings.Contains(grubPasswdOutput, "No GRUB password found")
	if !hasGrubPassword {
		rootSecurityIssues = append(rootSecurityIssues, "GRUB bootloader is not password protected")
	}

	// Too many wheel group members?
	wheelMembers := strings.Split(wheelMembersOutput, ",")
	tooManyWheelMembers := len(wheelMembers) > 5
	if tooManyWheelMembers {
		rootSecurityIssues = append(rootSecurityIssues, fmt.Sprintf("Too many users (%d) in wheel group with root access potential", len(wheelMembers)))
	}

	// Is su audited?
	hasSuAudit := !strings.Contains(suAuditOutput, "No TTY auditing for su configured")
	if !hasSuAudit {
		rootSecurityIssues = append(rootSecurityIssues, "TTY auditing not configured for su command")
	}

	// Evaluate root account security
	if len(rootSecurityIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d root account security issues", len(rootSecurityIssues)),
			report.ResultKeyRecommended)

		for _, issue := range rootSecurityIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if isRootLoginAllowed {
			report.AddRecommendation(&check.Result, "Change the root shell to /sbin/nologin in /etc/passwd to prevent direct logins")
		}

		if !isSecurettyEmpty && strings.Contains(consoleRootOutput, "console") {
			report.AddRecommendation(&check.Result, "Remove 'console' entry from /etc/securetty to prevent direct root console logins")
		}

		if !hasWheelConfig {
			report.AddRecommendation(&check.Result, "Configure wheel group in /etc/sudoers: '%wheel ALL=(ALL) ALL'")
		}

		if !hasRootTimeout {
			report.AddRecommendation(&check.Result, "Add timeout to /etc/profile.d/timeout.sh: 'TMOUT=300; readonly TMOUT; export TMOUT'")
		}

		if !hasGrubPassword {
			report.AddRecommendation(&check.Result, "Password-protect GRUB bootloader to prevent unauthorized single-user mode access")
		}

		if tooManyWheelMembers {
			report.AddRecommendation(&check.Result, "Limit wheel group membership to essential personnel only")
		}

		if !hasSuAudit {
			report.AddRecommendation(&check.Result, "Enable TTY auditing for su in /etc/pam.d/su: 'session required pam_tty_audit.so enable=root'")
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/configuring-automated-password-security_security-hardening", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Root account security appears to be properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkShellHistory validates shell history settings and retention
func checkShellHistory(r *report.AsciiDocReport) {
	checkID := "security-shell-history"
	checkName := "Shell History Configuration"
	checkDesc := "Checks shell history settings and retention configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Check global bash settings
	bashrcCmd := "grep -E 'HISTSIZE|HISTFILESIZE|histappend|HISTTIMEFORMAT|PROMPT_COMMAND' /etc/bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null || echo 'No global history settings found'"
	bashrcOutput, _ := utils.RunCommand("bash", "-c", bashrcCmd)

	// Check root's bash_history attributes
	rootHistAttrCmd := "lsattr /root/.bash_history 2>/dev/null || echo 'Unable to check attributes'"
	rootHistAttrOutput, _ := utils.RunCommand("bash", "-c", rootHistAttrCmd)

	// Check history sizes
	historySizesCmd := "grep -E 'HISTSIZE|HISTFILESIZE' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | sort -u || echo 'No history size settings found'"
	historySizesOutput, _ := utils.RunCommand("bash", "-c", historySizesCmd)

	// Check for history timestamp configuration
	historyTimeCmd := "grep -E 'HISTTIMEFORMAT' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null || echo 'No history timestamp format configured'"
	historyTimeOutput, _ := utils.RunCommand("bash", "-c", historyTimeCmd)

	// Check for histappend option
	histappendCmd := "grep -E 'shopt -s histappend' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null || echo 'histappend not configured'"
	histappendOutput, _ := utils.RunCommand("bash", "-c", histappendCmd)

	// Check PROMPT_COMMAND for history appending
	promptHistoryCmd := "grep -E 'PROMPT_COMMAND=.*history' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null || echo 'PROMPT_COMMAND history append not configured'"
	promptHistoryOutput, _ := utils.RunCommand("bash", "-c", promptHistoryCmd)

	// Check for syslog forwarding of commands
	historySyslogCmd := "grep -E 'PROMPT_COMMAND=.*logger' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null || echo 'Command logging to syslog not configured'"
	historySyslogOutput, _ := utils.RunCommand("bash", "-c", historySyslogCmd)

	var detail strings.Builder
	detail.WriteString("Shell History Configuration Analysis:\n\n")

	detail.WriteString("Global Bash History Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(bashrcOutput, "No global history settings found") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(bashrcOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Root Bash History File Attributes:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(rootHistAttrOutput, "Unable to check attributes") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(rootHistAttrOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("History Size Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(historySizesOutput, "No history size settings found") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(historySizesOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("History Timestamp Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(historyTimeOutput, "No history timestamp format configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(historyTimeOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("History Append Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(histappendOutput, "histappend not configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(histappendOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("PROMPT_COMMAND History Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(promptHistoryOutput, "PROMPT_COMMAND history append not configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(promptHistoryOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Command Logging to Syslog:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(historySyslogOutput, "Command logging to syslog not configured") {
		detail.WriteString("None\n")
	} else {
		detail.WriteString(historySyslogOutput)
	}
	detail.WriteString("\n----\n")

	// Check for issues
	historyIssues := []string{}

	// Check history size settings
	hasHistSizeConfig := !strings.Contains(historySizesOutput, "No history size settings found")
	smallHistSize := true
	smallHistFileSize := true

	if hasHistSizeConfig {
		// Extract history size values
		histSizeLines := strings.Split(historySizesOutput, "\n")
		for _, line := range histSizeLines {
			if strings.Contains(line, "HISTSIZE=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					sizeStr := strings.TrimSpace(parts[1])
					if size, err := strconv.Atoi(sizeStr); err == nil {
						if size >= 1000 {
							smallHistSize = false
						}
					}
				}
			}
			if strings.Contains(line, "HISTFILESIZE=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					sizeStr := strings.TrimSpace(parts[1])
					if size, err := strconv.Atoi(sizeStr); err == nil {
						if size >= 10000 {
							smallHistFileSize = false
						}
					}
				}
			}
		}
	}

	if !hasHistSizeConfig {
		historyIssues = append(historyIssues, "No history size configuration found")
	} else {
		if smallHistSize {
			historyIssues = append(historyIssues, "HISTSIZE is not set or too small (should be at least 1000)")
		}
		if smallHistFileSize {
			historyIssues = append(historyIssues, "HISTFILESIZE is not set or too small (should be at least 10000)")
		}
	}

	// Check timestamp format
	hasHistTimeFormat := !strings.Contains(historyTimeOutput, "No history timestamp format configured")
	if !hasHistTimeFormat {
		historyIssues = append(historyIssues, "History timestamp format not configured")
	}

	// Check histappend option
	hasHistAppend := !strings.Contains(histappendOutput, "histappend not configured")
	if !hasHistAppend {
		historyIssues = append(historyIssues, "History append option not configured")
	}

	// Check PROMPT_COMMAND for history
	hasPromptHistory := !strings.Contains(promptHistoryOutput, "PROMPT_COMMAND history append not configured")
	if !hasPromptHistory {
		historyIssues = append(historyIssues, "PROMPT_COMMAND not configured for immediate history preservation")
	}

	// Check root history append-only attribute
	hasAppendOnlyAttr := strings.Contains(rootHistAttrOutput, "----a----")
	if !hasAppendOnlyAttr {
		historyIssues = append(historyIssues, "Root's bash_history file is not set as append-only")
	}

	// Check command logging to syslog (optional)
	hasCommandLogging := !strings.Contains(historySyslogOutput, "Command logging to syslog not configured")
	// Not adding as an issue, but will include in recommendations if other issues exist

	// Evaluate shell history configuration
	if len(historyIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d shell history configuration issues", len(historyIssues)),
			report.ResultKeyRecommended)

		for _, issue := range historyIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		// Add specific recommendations based on issues
		if !hasHistSizeConfig || smallHistSize || smallHistFileSize {
			report.AddRecommendation(&check.Result, "Set appropriate history sizes in /etc/profile.d/history.sh:")
			report.AddRecommendation(&check.Result, "export HISTSIZE=10000")
			report.AddRecommendation(&check.Result, "export HISTFILESIZE=20000")
		}

		if !hasHistTimeFormat {
			report.AddRecommendation(&check.Result, "Add timestamp to history in /etc/profile.d/history.sh:")
			report.AddRecommendation(&check.Result, "export HISTTIMEFORMAT=\"%F %T \"")
		}

		if !hasHistAppend {
			report.AddRecommendation(&check.Result, "Enable history append mode in /etc/profile.d/history.sh:")
			report.AddRecommendation(&check.Result, "shopt -s histappend")
		}

		if !hasPromptHistory {
			report.AddRecommendation(&check.Result, "Configure PROMPT_COMMAND for immediate history in /etc/profile.d/history.sh:")
			report.AddRecommendation(&check.Result, "export PROMPT_COMMAND=\"history -a; history -n; $PROMPT_COMMAND\"")
		}

		if !hasAppendOnlyAttr {
			report.AddRecommendation(&check.Result, "Make root's history append-only: 'chattr +a /root/.bash_history'")
		}

		if !hasCommandLogging {
			report.AddRecommendation(&check.Result, "(Optional) Log commands to syslog by adding to /etc/profile.d/logging.sh:")
			report.AddRecommendation(&check.Result, "export PROMPT_COMMAND='history -a; history -n; logger -p local1.notice \"$(whoami)[$$]: $(history 1)\"'")
		}

		// Add reference link directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/assembly_securing-the-system-against-intrusion_security-hardening", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Shell history configuration appears to be properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
