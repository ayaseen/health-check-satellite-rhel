// pkg/checks/rhel/time.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunTimeChecks performs time configuration related checks
func RunTimeChecks(r *report.AsciiDocReport) {
	// Timezone check
	checkTimezone(r)

	// NTP/Chrony check
	checkTimeSync(r)

	// System clock consistency check
	checkClockConsistency(r)
}

// checkTimezone checks system timezone and regional settings
func checkTimezone(r *report.AsciiDocReport) {
	checkID := "time-timezone"
	checkName := "System Timezone"
	checkDesc := "Confirms system timezone and regional settings."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Get timezone information
	timezoneOutput, err := utils.RunCommand("timedatectl")
	timezoneString := strings.TrimSpace(timezoneOutput)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine system timezone", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure timedatectl is available (systemd-based systems).")
		report.AddRecommendation(&check.Result, "Check /etc/localtime symlink manually.")
		r.AddCheck(check)
		return
	}

	// Extract current timezone
	timezone := "Unknown"
	for _, line := range strings.Split(timezoneString, "\n") {
		if strings.Contains(line, "Time zone:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				timezone = strings.TrimSpace(parts[1])
				// Extract just the timezone if it includes additional info
				if strings.Contains(timezone, " ") {
					timezone = strings.Fields(timezone)[0]
				}
				break
			}
		}
	}

	// Get locale information
	localeOutput, _ := utils.RunCommand("localectl")

	var detail strings.Builder
	detail.WriteString("Timezone Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(timezoneOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nLocale Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(localeOutput)
	detail.WriteString("\n----\n")

	// Check if timezone is set
	if timezone == "Unknown" || timezone == "n/a" {
		check.Result = report.NewResult(report.StatusWarning,
			"System timezone not properly configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set the system timezone using 'timedatectl set-timezone <timezone>'.")
		report.AddRecommendation(&check.Result, "Use 'timedatectl list-timezones' to see available timezones.")

		// Add Red Hat specific documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("System timezone is set to %s", timezone),
			report.ResultKeyAdvisory)

		// Add a reminder to verify timezone is appropriate
		report.AddRecommendation(&check.Result, "Verify that the timezone matches the physical location or operational requirements of the server.")
		report.AddRecommendation(&check.Result, "To change timezone if needed: 'timedatectl set-timezone <timezone>'")
		report.AddRecommendation(&check.Result, "Common timezones: Asia/Riyadh (Saudi Arabia), Europe/London (UK), America/New_York (US Eastern)")

		// Add Red Hat specific documentation reference directly
		rhelVersion := utils.GetRedHatVersion()
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkTimeSync checks if NTP or Chrony is configured and synchronized
func checkTimeSync(r *report.AsciiDocReport) {
	checkID := "time-sync"
	checkName := "Time Synchronization"
	checkDesc := "Verifies NTP or Chrony is configured and synchronized."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Check for chronyd first (preferred in RHEL 7, 8, 9)
	chronyActive, _ := utils.RunCommand("systemctl", "is-active", "chronyd")
	chronyActive = strings.TrimSpace(chronyActive)

	// Check for ntpd (older versions of RHEL)
	ntpdActive, _ := utils.RunCommand("systemctl", "is-active", "ntpd")
	ntpdActive = strings.TrimSpace(ntpdActive)

	var detail strings.Builder
	detail.WriteString("Time Synchronization Status:\n\n")
	detail.WriteString("[source, bash]\n----\n")

	// Check which service is being used
	timeService := "none"
	if chronyActive == "active" {
		timeService = "chrony"
		detail.WriteString("Chrony service: active\n")

		// Get chrony sources
		chronySourcesCmd := "chronyc sources"
		chronySourcesOutput, _ := utils.RunCommand("bash", "-c", chronySourcesCmd)
		detail.WriteString("\nChrony Sources:\n")
		detail.WriteString(chronySourcesOutput)

		// Get chrony tracking
		chronyTrackingCmd := "chronyc tracking"
		chronyTrackingOutput, _ := utils.RunCommand("bash", "-c", chronyTrackingCmd)
		detail.WriteString("\nChrony Tracking:\n")
		detail.WriteString(chronyTrackingOutput)
	} else if ntpdActive == "active" {
		timeService = "ntp"
		detail.WriteString("NTP service: active\n")

		// Get NTP peers
		ntpPeersCmd := "ntpq -p"
		ntpPeersOutput, _ := utils.RunCommand("bash", "-c", ntpPeersCmd)
		detail.WriteString("\nNTP Peers:\n")
		detail.WriteString(ntpPeersOutput)
	} else {
		detail.WriteString("No time synchronization service is active.\n")
		detail.WriteString("Chrony service: " + chronyActive + "\n")
		detail.WriteString("NTP service: " + ntpdActive + "\n")
	}
	detail.WriteString("\n----\n")

	// Get timedatectl info about NTP sync
	timedatectlOutput, _ := utils.RunCommand("timedatectl")
	detail.WriteString("\nTimedate Control:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(timedatectlOutput)
	detail.WriteString("\n----\n")

	// Check if NTP synchronization is enabled according to timedatectl
	isNTPEnabled := strings.Contains(timedatectlOutput, "NTP enabled: yes") ||
		strings.Contains(timedatectlOutput, "Network time on: yes") ||
		timeService != "none"

	// Check if system clock is synchronized
	isSynced := strings.Contains(timedatectlOutput, "NTP synchronized: yes") ||
		strings.Contains(timedatectlOutput, "System clock synchronized: yes")

	rhelVersion := utils.GetRedHatVersion()
	if !isNTPEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Time synchronization is not enabled",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install and configure chrony using 'yum install chrony'.")
		report.AddRecommendation(&check.Result, "Enable and start the chrony service: 'systemctl enable --now chronyd'.")
		report.AddRecommendation(&check.Result, "Enable NTP synchronization: 'timedatectl set-ntp true'.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	} else if !isSynced {
		check.Result = report.NewResult(report.StatusWarning,
			"Time synchronization is enabled but not synchronized",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check firewall rules to ensure NTP traffic is allowed.")
		report.AddRecommendation(&check.Result, "Verify time sources in /etc/chrony.conf or /etc/ntp.conf.")
		report.AddRecommendation(&check.Result, "Check for network connectivity to time servers.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Time synchronization is active and using %s", timeService),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkClockConsistency ensures system clock is consistent with infrastructure standards
func checkClockConsistency(r *report.AsciiDocReport) {
	checkID := "clock-consistency"
	checkName := "Clock Consistency"
	checkDesc := "Ensures system clock is consistent with infrastructure standards."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySystemInfo)

	// Get current system time
	dateOutput, err := utils.RunCommand("date", "+%Y-%m-%d %H:%M:%S")
	systemTime := strings.TrimSpace(dateOutput)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine system time", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if date command is available.")
		r.AddCheck(check)
		return
	}

	// Check if RTC is in local time or UTC
	rtcInfoCmd := "timedatectl | grep \"RTC in local\""
	rtcInfoOutput, _ := utils.RunCommand("bash", "-c", rtcInfoCmd)
	rtcInLocal := strings.Contains(rtcInfoOutput, "yes")

	// Get hardware clock time
	hwClockOutput, _ := utils.RunCommand("hwclock", "--show")
	hwClockTime := strings.TrimSpace(hwClockOutput)

	var detail strings.Builder
	detail.WriteString("Clock Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("System Time: %s\n", systemTime))
	detail.WriteString(fmt.Sprintf("Hardware Clock Time: %s\n", hwClockTime))
	detail.WriteString(fmt.Sprintf("RTC in local time: %v\n", rtcInLocal))
	detail.WriteString("\n----\n")

	// Check if hardware clock and system time are inconsistent
	// Note: This is a simplistic check, in a real implementation
	// we would parse and compare the times more carefully
	timeDifference := false
	if hwClockTime != "" && !strings.Contains(hwClockTime, systemTime[:10]) {
		timeDifference = true
	}

	rhelVersion := utils.GetRedHatVersion()
	if rtcInLocal {
		check.Result = report.NewResult(report.StatusWarning,
			"RTC is set to local time instead of UTC",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set RTC to UTC time: 'timedatectl set-local-rtc 0'.")
		report.AddRecommendation(&check.Result, "This is especially important for dual-boot systems.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	} else if timeDifference {
		check.Result = report.NewResult(report.StatusWarning,
			"System time and hardware clock time appear to be inconsistent",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Synchronize hardware clock with system time: 'hwclock --systohc'.")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_basic_system_settings/index", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System clock appears to be consistent",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
