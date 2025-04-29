// pkg/checks/rhel/compliance.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// ComplianceScore represents a component of the overall compliance score
type ComplianceScore struct {
	Category        string
	Score           int
	MaxScore        int
	Details         []string
	Recommendations []string
}

// RunComplianceChecks performs compliance related checks
func RunComplianceChecks(r *report.AsciiDocReport) {
	// Check RHEL CIS compliance
	checkRHELCISCompliance(r)
}

// checkRHELCISCompliance checks RHEL CIS compliance and best practices
func checkRHELCISCompliance(r *report.AsciiDocReport) {
	checkID := "compliance-rhel-cis"
	checkName := "RHEL CIS Compliance"
	checkDesc := "Checks system against RHEL CIS benchmarks and Red Hat best practices."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySecurity)

	// Initialize scores for each category
	scores := []ComplianceScore{
		{Category: "Partitioning", Score: 0, MaxScore: 10},
		{Category: "Filesystem Configuration", Score: 0, MaxScore: 10},
		{Category: "Authentication", Score: 0, MaxScore: 10},
		{Category: "Network Security", Score: 0, MaxScore: 10},
		{Category: "Services", Score: 0, MaxScore: 10},
		{Category: "SELinux & MAC", Score: 0, MaxScore: 10},
		{Category: "System Updates", Score: 0, MaxScore: 10},
		{Category: "Logging & Auditing", Score: 0, MaxScore: 10},
		{Category: "Time Synchronization", Score: 0, MaxScore: 10},
		{Category: "Additional Security", Score: 0, MaxScore: 10},
	}

	// Get RHEL version for documentation references
	rhelVersion := utils.GetRedHatVersion()

	// Check partitioning - verify separate partitions for /home, /tmp, /var, /var/log, /var/tmp
	mountsCmd := "mount | grep -E '(/home|/tmp|/var|/var/log|/var/tmp) '"
	mountsOutput, _ := utils.RunCommand("bash", "-c", mountsCmd)

	// Get all mount points for parsing
	allMountsCmd := "mount | grep -E '^/dev'"
	allMountsOutput, _ := utils.RunCommand("bash", "-c", allMountsCmd)

	// Parse mount points and count separate partitions
	separatePartitionCount := 0
	expectedPartitions := []string{"/home", "/tmp", "/var", "/var/log", "/var/tmp"}
	for _, partition := range expectedPartitions {
		if strings.Contains(mountsOutput, " "+partition+" ") {
			separatePartitionCount++
			scores[0].Details = append(scores[0].Details, fmt.Sprintf("✓ %s is on a separate partition", partition))
		} else {
			scores[0].Details = append(scores[0].Details, fmt.Sprintf("✗ %s is NOT on a separate partition", partition))
			scores[0].Recommendations = append(scores[0].Recommendations, fmt.Sprintf("Create a separate partition for %s", partition))
		}
	}
	scores[0].Score = (separatePartitionCount * scores[0].MaxScore) / len(expectedPartitions)

	// Check filesystem mount options (nodev, nosuid, noexec)
	secureOptionsCount := 0
	totalChecks := 0

	// Check /tmp options
	if strings.Contains(allMountsOutput, " /tmp ") {
		totalChecks += 3
		if strings.Contains(allMountsOutput, "nodev") && strings.Contains(mountsOutput, "/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /tmp has nodev option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /tmp lacks nodev option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add nodev option to /tmp mount")
		}

		if strings.Contains(allMountsOutput, "nosuid") && strings.Contains(mountsOutput, "/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /tmp has nosuid option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /tmp lacks nosuid option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add nosuid option to /tmp mount")
		}

		if strings.Contains(allMountsOutput, "noexec") && strings.Contains(mountsOutput, "/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /tmp has noexec option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /tmp lacks noexec option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add noexec option to /tmp mount")
		}
	}

	// Check /var/tmp options
	if strings.Contains(allMountsOutput, " /var/tmp ") {
		totalChecks += 3
		if strings.Contains(allMountsOutput, "nodev") && strings.Contains(mountsOutput, "/var/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /var/tmp has nodev option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /var/tmp lacks nodev option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add nodev option to /var/tmp mount")
		}

		if strings.Contains(allMountsOutput, "nosuid") && strings.Contains(mountsOutput, "/var/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /var/tmp has nosuid option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /var/tmp lacks nosuid option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add nosuid option to /var/tmp mount")
		}

		if strings.Contains(allMountsOutput, "noexec") && strings.Contains(mountsOutput, "/var/tmp") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /var/tmp has noexec option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /var/tmp lacks noexec option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add noexec option to /var/tmp mount")
		}
	}

	// Check /home options
	if strings.Contains(allMountsOutput, " /home ") {
		totalChecks += 1
		if strings.Contains(allMountsOutput, "nodev") && strings.Contains(mountsOutput, "/home") {
			secureOptionsCount++
			scores[1].Details = append(scores[1].Details, "✓ /home has nodev option")
		} else {
			scores[1].Details = append(scores[1].Details, "✗ /home lacks nodev option")
			scores[1].Recommendations = append(scores[1].Recommendations, "Add nodev option to /home mount")
		}
	}

	// Calculate filesystem score
	if totalChecks > 0 {
		scores[1].Score = (secureOptionsCount * scores[1].MaxScore) / totalChecks
	} else {
		scores[1].Score = 0
		scores[1].Details = append(scores[1].Details, "No filesystem options checked")
	}

	// Check authentication (Red Hat IDM, SSSD, PAM)
	authPoints := 0
	authMaxPoints := 5

	// Check SSSD
	sssdCmd := "rpm -q sssd || echo 'not-installed'"
	sssdOutput, _ := utils.RunCommand("bash", "-c", sssdCmd)
	if !strings.Contains(sssdOutput, "not-installed") {
		authPoints++
		scores[2].Details = append(scores[2].Details, "✓ SSSD is installed")

		// Check if SSSD service is running
		sssdServiceCmd := "systemctl is-active sssd"
		sssdServiceOutput, _ := utils.RunCommand("bash", "-c", sssdServiceCmd)
		if strings.TrimSpace(sssdServiceOutput) == "active" {
			authPoints++
			scores[2].Details = append(scores[2].Details, "✓ SSSD service is active")
		} else {
			scores[2].Details = append(scores[2].Details, "✗ SSSD service is not active")
			scores[2].Recommendations = append(scores[2].Recommendations, "Start SSSD service: 'systemctl start sssd'")
		}
	} else {
		scores[2].Details = append(scores[2].Details, "✗ SSSD is not installed")
		scores[2].Recommendations = append(scores[2].Recommendations, "Install SSSD: 'yum install sssd'")
	}

	// Check for IDM/AD integration
	idmCmd := "realm list || echo 'no-realm'"
	idmOutput, _ := utils.RunCommand("bash", "-c", idmCmd)
	if !strings.Contains(idmOutput, "no-realm") && strings.TrimSpace(idmOutput) != "" {
		authPoints++
		scores[2].Details = append(scores[2].Details, "✓ System is joined to a realm (IDM or AD)")
	} else {
		scores[2].Details = append(scores[2].Details, "✗ System is not joined to Red Hat IDM or Active Directory")
		scores[2].Recommendations = append(scores[2].Recommendations, "Join system to Red Hat IDM or Active Directory")
	}

	// Check PAM for proper configuration
	pamCmd := "grep pam_pwquality /etc/pam.d/password-auth || echo 'not-configured'"
	pamOutput, _ := utils.RunCommand("bash", "-c", pamCmd)
	if !strings.Contains(pamOutput, "not-configured") {
		authPoints++
		scores[2].Details = append(scores[2].Details, "✓ PAM has password quality requirements")
	} else {
		scores[2].Details = append(scores[2].Details, "✗ PAM password quality requirements not configured")
		scores[2].Recommendations = append(scores[2].Recommendations, "Configure PAM password quality checks")
	}

	// Calculate auth score
	scores[2].Score = (authPoints * scores[2].MaxScore) / authMaxPoints

	// Check network security (firewall, SSH config)
	netPoints := 0
	netMaxPoints := 5

	// Check firewall
	firewallCmd := "systemctl is-active firewalld || echo 'not-active'"
	firewallOutput, _ := utils.RunCommand("bash", "-c", firewallCmd)
	if strings.TrimSpace(firewallOutput) == "active" {
		netPoints++
		scores[3].Details = append(scores[3].Details, "✓ Firewall (firewalld) is active")

		// Check default zone
		firewallZoneCmd := "firewall-cmd --get-default-zone"
		firewallZoneOutput, _ := utils.RunCommand("bash", "-c", firewallZoneCmd)
		if strings.TrimSpace(firewallZoneOutput) != "public" && strings.TrimSpace(firewallZoneOutput) != "" {
			netPoints++
			scores[3].Details = append(scores[3].Details, fmt.Sprintf("✓ Firewall default zone is custom: %s", strings.TrimSpace(firewallZoneOutput)))
		} else {
			scores[3].Details = append(scores[3].Details, "✗ Firewall using default 'public' zone")
			scores[3].Recommendations = append(scores[3].Recommendations, "Consider using a custom firewall zone")
		}
	} else {
		scores[3].Details = append(scores[3].Details, "✗ Firewall (firewalld) is not active")
		scores[3].Recommendations = append(scores[3].Recommendations, "Enable firewalld: 'systemctl enable --now firewalld'")
	}

	// Check SSH configuration
	sshConfigCmd := "grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config || echo 'not-configured'"
	sshConfigOutput, _ := utils.RunCommand("bash", "-c", sshConfigCmd)

	if strings.Contains(sshConfigOutput, "PermitRootLogin no") {
		netPoints++
		scores[3].Details = append(scores[3].Details, "✓ SSH root login is disabled")
	} else {
		scores[3].Details = append(scores[3].Details, "✗ SSH root login is not explicitly disabled")
		scores[3].Recommendations = append(scores[3].Recommendations, "Disable SSH root login: 'PermitRootLogin no'")
	}

	if strings.Contains(sshConfigOutput, "PasswordAuthentication no") {
		netPoints++
		scores[3].Details = append(scores[3].Details, "✓ SSH password authentication is disabled")
	} else {
		scores[3].Details = append(scores[3].Details, "✗ SSH password authentication is not disabled")
		scores[3].Recommendations = append(scores[3].Recommendations, "Disable SSH password auth: 'PasswordAuthentication no'")
	}

	// Calculate network score
	scores[3].Score = (netPoints * scores[3].MaxScore) / netMaxPoints

	// Check services (disabled unnecessary services)
	servicePoints := 0
	serviceMaxPoints := 5

	// List of services that should be disabled
	unnecessaryServices := []string{
		"telnet", "rsh", "rlogin", "rcp", "ypserv", "ypbind", "tftp",
		"talk", "xinetd", "avahi-daemon", "cups",
	}

	disabledCount := 0
	for _, service := range unnecessaryServices {
		serviceCmd := fmt.Sprintf("systemctl is-enabled %s 2>/dev/null || echo 'not-installed'", service)
		serviceOutput, _ := utils.RunCommand("bash", "-c", serviceCmd)
		if strings.TrimSpace(serviceOutput) == "disabled" || strings.Contains(serviceOutput, "not-installed") {
			disabledCount++
		} else if strings.TrimSpace(serviceOutput) == "enabled" {
			scores[4].Details = append(scores[4].Details, fmt.Sprintf("✗ Unnecessary service %s is enabled", service))
			scores[4].Recommendations = append(scores[4].Recommendations, fmt.Sprintf("Disable %s service: 'systemctl disable %s'", service, service))
		}
	}

	// Calculate percentage of unnecessary services properly configured
	servicePoints += (disabledCount * 3) / len(unnecessaryServices)
	scores[4].Details = append(scores[4].Details, fmt.Sprintf("✓ %d/%d unnecessary services are disabled or not installed", disabledCount, len(unnecessaryServices)))

	// Check if only necessary services are enabled at boot
	autostartCmd := "systemctl list-unit-files --type=service --state=enabled | wc -l"
	autostartOutput, _ := utils.RunCommand("bash", "-c", autostartCmd)
	autostartCount, _ := strconv.Atoi(strings.TrimSpace(autostartOutput))

	if autostartCount < 20 {
		servicePoints += 2
		scores[4].Details = append(scores[4].Details, fmt.Sprintf("✓ Low number of enabled services: %d", autostartCount))
	} else if autostartCount < 30 {
		servicePoints += 1
		scores[4].Details = append(scores[4].Details, fmt.Sprintf("⚠ Moderate number of enabled services: %d", autostartCount))
		scores[4].Recommendations = append(scores[4].Recommendations, "Review enabled services and disable unnecessary ones")
	} else {
		scores[4].Details = append(scores[4].Details, fmt.Sprintf("✗ High number of enabled services: %d", autostartCount))
		scores[4].Recommendations = append(scores[4].Recommendations, "Review and reduce the number of enabled services")
	}

	// Calculate services score
	scores[4].Score = (servicePoints * scores[4].MaxScore) / serviceMaxPoints

	// Check SELinux
	selinuxPoints := 0
	selinuxMaxPoints := 3

	// Check SELinux status
	selinuxCmd := "getenforce"
	selinuxOutput, _ := utils.RunCommand("bash", "-c", selinuxCmd)
	if strings.TrimSpace(selinuxOutput) == "Enforcing" {
		selinuxPoints += 2
		scores[5].Details = append(scores[5].Details, "✓ SELinux is in enforcing mode")
	} else if strings.TrimSpace(selinuxOutput) == "Permissive" {
		selinuxPoints += 1
		scores[5].Details = append(scores[5].Details, "⚠ SELinux is in permissive mode")
		scores[5].Recommendations = append(scores[5].Recommendations, "Set SELinux to enforcing mode")
	} else {
		scores[5].Details = append(scores[5].Details, "✗ SELinux is disabled")
		scores[5].Recommendations = append(scores[5].Recommendations, "Enable SELinux in enforcing mode")
	}

	// Check SELinux policy
	selinuxPolicyCmd := "grep ^SELINUXTYPE /etc/selinux/config"
	selinuxPolicyOutput, _ := utils.RunCommand("bash", "-c", selinuxPolicyCmd)
	if strings.Contains(selinuxPolicyOutput, "targeted") {
		selinuxPoints++
		scores[5].Details = append(scores[5].Details, "✓ SELinux policy is set to targeted")
	} else {
		scores[5].Details = append(scores[5].Details, "✗ SELinux policy is not set to targeted")
		scores[5].Recommendations = append(scores[5].Recommendations, "Set SELinux policy to targeted")
	}

	// Calculate SELinux score
	scores[5].Score = (selinuxPoints * scores[5].MaxScore) / selinuxMaxPoints

	// Check system updates
	updatePoints := 0
	updateMaxPoints := 4

	// Check for security updates
	securityUpdatesCmd := "yum check-update --security -q | grep -i sec | wc -l"
	securityUpdatesOutput, _ := utils.RunCommand("bash", "-c", securityUpdatesCmd)
	securityUpdateCount, _ := strconv.Atoi(strings.TrimSpace(securityUpdatesOutput))

	if securityUpdateCount == 0 {
		updatePoints += 3
		scores[6].Details = append(scores[6].Details, "✓ No security updates pending")
	} else if securityUpdateCount < 5 {
		updatePoints += 1
		scores[6].Details = append(scores[6].Details, fmt.Sprintf("⚠ %d security updates pending", securityUpdateCount))
		scores[6].Recommendations = append(scores[6].Recommendations, "Apply security updates: 'yum update --security'")
	} else {
		scores[6].Details = append(scores[6].Details, fmt.Sprintf("✗ %d security updates pending", securityUpdateCount))
		scores[6].Recommendations = append(scores[6].Recommendations, "Apply security updates: 'yum update --security'")
	}

	// Check if yum-cron or dnf-automatic is installed for automatic updates
	autoupdateCmd := "rpm -q yum-cron dnf-automatic || echo 'not-installed'"
	autoupdateOutput, _ := utils.RunCommand("bash", "-c", autoupdateCmd)
	if !strings.Contains(autoupdateOutput, "not-installed") {
		updatePoints++
		scores[6].Details = append(scores[6].Details, "✓ Automatic updates are configured")
	} else {
		scores[6].Details = append(scores[6].Details, "✗ Automatic updates are not configured")
		scores[6].Recommendations = append(scores[6].Recommendations, "Install automatic updates: 'yum install yum-cron' or 'yum install dnf-automatic'")
	}

	// Calculate updates score
	scores[6].Score = (updatePoints * scores[6].MaxScore) / updateMaxPoints

	// Check logging & auditing
	loggingPoints := 0
	loggingMaxPoints := 5

	// Check if rsyslog or journal is configured
	rsyslogCmd := "systemctl is-active rsyslog || echo 'not-active'"
	rsyslogOutput, _ := utils.RunCommand("bash", "-c", rsyslogCmd)
	if strings.TrimSpace(rsyslogOutput) == "active" {
		loggingPoints++
		scores[7].Details = append(scores[7].Details, "✓ rsyslog service is active")
	} else {
		scores[7].Details = append(scores[7].Details, "✗ rsyslog service is not active")
		scores[7].Recommendations = append(scores[7].Recommendations, "Enable rsyslog: 'systemctl enable --now rsyslog'")
	}

	// Check auditd configuration
	auditdCmd := "systemctl is-active auditd || echo 'not-active'"
	auditdOutput, _ := utils.RunCommand("bash", "-c", auditdCmd)
	if strings.TrimSpace(auditdOutput) == "active" {
		loggingPoints++
		scores[7].Details = append(scores[7].Details, "✓ auditd service is active")

		// Check audit rules
		auditRulesCmd := "auditctl -l | wc -l"
		auditRulesOutput, _ := utils.RunCommand("bash", "-c", auditRulesCmd)
		auditRuleCount, _ := strconv.Atoi(strings.TrimSpace(auditRulesOutput))

		if auditRuleCount > 10 {
			loggingPoints++
			scores[7].Details = append(scores[7].Details, fmt.Sprintf("✓ %d audit rules configured", auditRuleCount))
		} else {
			scores[7].Details = append(scores[7].Details, fmt.Sprintf("⚠ Only %d audit rules configured", auditRuleCount))
			scores[7].Recommendations = append(scores[7].Recommendations, "Configure more audit rules")
		}
	} else {
		scores[7].Details = append(scores[7].Details, "✗ auditd service is not active")
		scores[7].Recommendations = append(scores[7].Recommendations, "Enable auditd: 'systemctl enable --now auditd'")
	}

	// Check log rotation
	logrotateCmd := "grep -E 'weekly|monthly|rotate' /etc/logrotate.conf | wc -l"
	logrotateOutput, _ := utils.RunCommand("bash", "-c", logrotateCmd)
	logrotateCount, _ := strconv.Atoi(strings.TrimSpace(logrotateOutput))

	if logrotateCount > 2 {
		loggingPoints++
		scores[7].Details = append(scores[7].Details, "✓ Log rotation is configured")
	} else {
		scores[7].Details = append(scores[7].Details, "✗ Log rotation may not be properly configured")
		scores[7].Recommendations = append(scores[7].Recommendations, "Review and configure log rotation settings")
	}

	// Calculate logging score
	scores[7].Score = (loggingPoints * scores[7].MaxScore) / loggingMaxPoints

	// Check time synchronization
	timePoints := 0
	timeMaxPoints := 3

	// Check if chrony or ntpd is active
	chronyCmd := "systemctl is-active chronyd || echo 'not-active'"
	chronyOutput, _ := utils.RunCommand("bash", "-c", chronyCmd)
	ntpdCmd := "systemctl is-active ntpd || echo 'not-active'"
	ntpdOutput, _ := utils.RunCommand("bash", "-c", ntpdCmd)

	if strings.TrimSpace(chronyOutput) == "active" || strings.TrimSpace(ntpdOutput) == "active" {
		timePoints++
		if strings.TrimSpace(chronyOutput) == "active" {
			scores[8].Details = append(scores[8].Details, "✓ chronyd service is active")
		} else {
			scores[8].Details = append(scores[8].Details, "✓ ntpd service is active")
		}

		// Check synchronization
		timeSyncCmd := "timedatectl status | grep 'synchronized: yes'"
		timeSyncOutput, _ := utils.RunCommand("bash", "-c", timeSyncCmd)
		if strings.TrimSpace(timeSyncOutput) != "" {
			timePoints++
			scores[8].Details = append(scores[8].Details, "✓ System clock is synchronized")
		} else {
			scores[8].Details = append(scores[8].Details, "✗ System clock is not synchronized")
			scores[8].Recommendations = append(scores[8].Recommendations, "Check time synchronization settings")
		}
	} else {
		scores[8].Details = append(scores[8].Details, "✗ No time synchronization service is active")
		scores[8].Recommendations = append(scores[8].Recommendations, "Enable chronyd: 'systemctl enable --now chronyd'")
	}

	// Check timezone
	timezoneCmd := "timedatectl | grep 'Time zone'"
	timezoneOutput, _ := utils.RunCommand("bash", "-c", timezoneCmd)
	if strings.TrimSpace(timezoneOutput) != "" {
		timePoints++
		scores[8].Details = append(scores[8].Details, fmt.Sprintf("✓ Timezone configured: %s", strings.TrimSpace(timezoneOutput)))
	} else {
		scores[8].Details = append(scores[8].Details, "✗ Timezone not properly configured")
		scores[8].Recommendations = append(scores[8].Recommendations, "Set timezone with timedatectl")
	}

	// Calculate time sync score
	scores[8].Score = (timePoints * scores[8].MaxScore) / timeMaxPoints

	// Check additional security measures
	secPoints := 0
	secMaxPoints := 5

	// Check if AIDE is installed
	aideCmd := "rpm -q aide || echo 'not-installed'"
	aideOutput, _ := utils.RunCommand("bash", "-c", aideCmd)
	if !strings.Contains(aideOutput, "not-installed") {
		secPoints++
		scores[9].Details = append(scores[9].Details, "✓ AIDE (file integrity) is installed")
	} else {
		scores[9].Details = append(scores[9].Details, "✗ AIDE (file integrity) is not installed")
		scores[9].Recommendations = append(scores[9].Recommendations, "Install AIDE: 'yum install aide'")
	}

	// Check password requirements
	passwdReqCmd := "grep ^PASS_MIN_LEN /etc/login.defs || echo 'not-set'"
	passwdReqOutput, _ := utils.RunCommand("bash", "-c", passwdReqCmd)
	if !strings.Contains(passwdReqOutput, "not-set") {
		// Extract the length
		parts := strings.Fields(passwdReqOutput)
		if len(parts) > 1 {
			minLen, _ := strconv.Atoi(parts[1])
			if minLen >= 8 {
				secPoints++
				scores[9].Details = append(scores[9].Details, fmt.Sprintf("✓ Password minimum length is %d", minLen))
			} else {
				scores[9].Details = append(scores[9].Details, fmt.Sprintf("⚠ Password minimum length is only %d", minLen))
				scores[9].Recommendations = append(scores[9].Recommendations, "Increase password minimum length to 8 or more")
			}
		}
	} else {
		scores[9].Details = append(scores[9].Details, "✗ Password minimum length not set")
		scores[9].Recommendations = append(scores[9].Recommendations, "Set password minimum length in /etc/login.defs")
	}

	// Check failed login lockout
	lockoutCmd := "grep -E 'pam_faillock|pam_tally2' /etc/pam.d/system-auth || echo 'not-configured'"
	lockoutOutput, _ := utils.RunCommand("bash", "-c", lockoutCmd)
	if !strings.Contains(lockoutOutput, "not-configured") {
		secPoints++
		scores[9].Details = append(scores[9].Details, "✓ Account lockout after failed logins is configured")
	} else {
		scores[9].Details = append(scores[9].Details, "✗ Account lockout after failed logins is not configured")
		scores[9].Recommendations = append(scores[9].Recommendations, "Configure account lockout with pam_faillock")
	}

	// Check grub password protection
	grubCmd := "grep password /boot/grub2/grub.cfg || echo 'not-configured'"
	grubOutput, _ := utils.RunCommand("bash", "-c", grubCmd)
	if !strings.Contains(grubOutput, "not-configured") && strings.Contains(grubOutput, "password") {
		secPoints++
		scores[9].Details = append(scores[9].Details, "✓ GRUB boot password is configured")
	} else {
		scores[9].Details = append(scores[9].Details, "✗ GRUB boot password is not configured")
		scores[9].Recommendations = append(scores[9].Recommendations, "Configure GRUB password protection")
	}

	// Check USB storage disable
	usbCmd := "grep -i 'install usb-storage /bin/true' /etc/modprobe.d/* || echo 'not-disabled'"
	usbOutput, _ := utils.RunCommand("bash", "-c", usbCmd)
	if !strings.Contains(usbOutput, "not-disabled") {
		secPoints++
		scores[9].Details = append(scores[9].Details, "✓ USB storage is disabled by policy")
	} else {
		scores[9].Details = append(scores[9].Details, "⚠ USB storage is not disabled by policy")
		scores[9].Recommendations = append(scores[9].Recommendations, "Consider disabling USB storage if not needed")
	}

	// Calculate additional security score
	scores[9].Score = (secPoints * scores[9].MaxScore) / secMaxPoints

	// Calculate total score
	totalScore := 0
	maxPossibleScore := 0
	for _, s := range scores {
		totalScore += s.Score
		maxPossibleScore += s.MaxScore
	}

	// Create the report
	var detail strings.Builder
	detail.WriteString("RHEL CIS Compliance and Best Practices Report\n\n")
	detail.WriteString(fmt.Sprintf("Overall Score: %d/%d (%d%%)\n\n",
		totalScore, maxPossibleScore, (totalScore * 100 / maxPossibleScore)))

	// Add category scores
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Category Scores:\n")

	// Create a table for category scores
	detail.WriteString("[cols=\"2,1,1,1\", options=\"header\"]\n")
	detail.WriteString("|===\n")
	detail.WriteString("|Category|Score|Max Score|Percentage\n")

	for _, s := range scores {
		percentage := 0
		if s.MaxScore > 0 {
			percentage = (s.Score * 100 / s.MaxScore)
		}
		detail.WriteString(fmt.Sprintf("|%s|%d|%d|%d%%\n",
			s.Category, s.Score, s.MaxScore, percentage))
	}
	detail.WriteString("|===\n\n")

	// Add detailed findings and recommendations for each category
	detail.WriteString("\n== Detailed Findings:\n")
	for _, s := range scores {
		detail.WriteString(fmt.Sprintf("\n=== %s (%d/%d)\n", s.Category, s.Score, s.MaxScore))
		for _, d := range s.Details {
			detail.WriteString("* " + d + "\n")
		}

		if len(s.Recommendations) > 0 {
			detail.WriteString("\nRecommendations:\n")
			for _, r := range s.Recommendations {
				detail.WriteString("* " + r + "\n")
			}
		}
	}

	// Determine overall compliance status
	var status report.Status
	var resultKey report.ResultKey
	var message string

	compliancePercent := totalScore * 100 / maxPossibleScore

	if compliancePercent >= 90 {
		status = report.StatusOK
		resultKey = report.ResultKeyNoChange
		message = fmt.Sprintf("System is highly compliant with RHEL CIS standards (%d%%)", compliancePercent)
	} else if compliancePercent >= 70 {
		status = report.StatusWarning
		resultKey = report.ResultKeyRecommended
		message = fmt.Sprintf("System is moderately compliant with RHEL CIS standards (%d%%)", compliancePercent)
	} else {
		status = report.StatusCritical
		resultKey = report.ResultKeyRequired
		message = fmt.Sprintf("System has low compliance with RHEL CIS standards (%d%%)", compliancePercent)
	}

	check.Result = report.NewResult(status, message, resultKey)

	// Add top recommendations (up to 5)
	allRecommendations := []string{}
	for _, s := range scores {
		allRecommendations = append(allRecommendations, s.Recommendations...)
	}

	// Add up to 5 recommendations
	recommendationCount := 0
	for _, recommendation := range allRecommendations {
		if recommendationCount < 5 {
			report.AddRecommendation(&check.Result, recommendation)
			recommendationCount++
		} else {
			break
		}
	}

	if recommendationCount == 5 && len(allRecommendations) > 5 {
		report.AddRecommendation(&check.Result, fmt.Sprintf("... and %d more recommendations (see details)", len(allRecommendations)-5))
	}

	// Add CIS Benchmark documentation reference directly as a link
	report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/index", rhelVersion))

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
