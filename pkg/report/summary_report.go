// pkg/report/summary_report.go

package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SummaryReport generates consolidated summary reports from multiple host reports
type SummaryReport struct {
	HostReports      map[string]*AsciiDocReport
	GeneratedTime    time.Time
	OutputDir        string
	TotalHosts       int
	HostsByType      map[string]int
	CriticalCount    int
	WarningCount     int
	AdvisoryCount    int
	HealthyHostCount int
}

// HostSummary contains summary information for a single host
type HostSummary struct {
	Hostname      string
	Type          string
	CriticalCount int
	WarningCount  int
	AdvisoryCount int
	OverallStatus Status
	Issues        []IssueSummary
}

// IssueSummary represents a single issue found
type IssueSummary struct {
	Category    Category
	CheckName   string
	Message     string
	Severity    ResultKey
	Hosts       []string
	Remediation string
}

// NewSummaryReport creates a new summary report
func NewSummaryReport(outputDir string) *SummaryReport {
	return &SummaryReport{
		HostReports:   make(map[string]*AsciiDocReport),
		GeneratedTime: time.Now(),
		OutputDir:     outputDir,
		HostsByType:   make(map[string]int),
	}
}

// AddHostReport adds a host report to the summary
func (s *SummaryReport) AddHostReport(hostname string, report *AsciiDocReport) {
	s.HostReports[hostname] = report
	s.TotalHosts++
}

// GenerateAllReports generates all summary reports
func (s *SummaryReport) GenerateAllReports() error {
	// First analyze all host reports
	s.analyzeReports()

	// Generate main summary report
	if err := s.GenerateSummaryReport(); err != nil {
		return fmt.Errorf("failed to generate summary report: %v", err)
	}

	// Generate critical issues report
	if err := s.GenerateCriticalIssuesReport(); err != nil {
		return fmt.Errorf("failed to generate critical issues report: %v", err)
	}

	return nil
}

// analyzeReports analyzes all host reports to gather statistics
func (s *SummaryReport) analyzeReports() {
	for _, report := range s.HostReports {
		hostType := "RHEL"
		if strings.Contains(report.Title, "Satellite") {
			hostType = "Satellite"
		}
		s.HostsByType[hostType]++

		criticalCount := 0
		warningCount := 0
		advisoryCount := 0

		for _, check := range report.Checks {
			switch check.Result.ResultKey {
			case ResultKeyRequired:
				criticalCount++
				s.CriticalCount++
			case ResultKeyRecommended:
				warningCount++
				s.WarningCount++
			case ResultKeyAdvisory:
				advisoryCount++
				s.AdvisoryCount++
			}
		}

		if criticalCount == 0 && warningCount == 0 {
			s.HealthyHostCount++
		}
	}
}

// GenerateSummaryReport generates the main consolidated summary report
func (s *SummaryReport) GenerateSummaryReport() error {
	filename := filepath.Join(s.OutputDir, fmt.Sprintf("%s-infrastructure-summary.adoc",
		s.GeneratedTime.Format("2006-01-02-150405")))

	var content strings.Builder

	// Header
	content.WriteString("= Infrastructure Health Check Summary\n")
	content.WriteString(fmt.Sprintf("Generated: %s\n", s.GeneratedTime.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Total Hosts: %d | Critical: %d | Warnings: %d | Healthy: %d\n\n",
		s.TotalHosts, s.CriticalCount, s.WarningCount, s.HealthyHostCount))

	// Add the Key section (only appears here)
	content.WriteString(s.generateKeySection())

	// Executive Dashboard
	content.WriteString("== Executive Dashboard\n\n")
	content.WriteString(s.generateDashboard())

	// Critical Issues
	criticalIssues := s.groupIssuesBySeverity(ResultKeyRequired)
	if len(criticalIssues) > 0 {
		content.WriteString("== PRIORITY 1: Critical Issues Requiring Immediate Action\n\n")
		content.WriteString(s.formatGroupedIssues(criticalIssues))
	}

	// Warnings
	warnings := s.groupIssuesBySeverity(ResultKeyRecommended)
	if len(warnings) > 0 {
		content.WriteString("== PRIORITY 2: Warnings - Plan to Address Soon\n\n")
		content.WriteString(s.formatGroupedIssues(warnings))
	}

	// Pattern Analysis
	content.WriteString("== System Patterns & Trends\n\n")
	content.WriteString(s.generatePatternAnalysis())

	// Host Health Matrix
	content.WriteString("== Host Health Matrix\n\n")
	content.WriteString(s.generateHealthMatrix())

	// Links to individual reports
	content.WriteString("== Individual Host Reports\n\n")
	content.WriteString("Detailed reports for each host are available in the `hosts/` directory:\n\n")

	// Sort hostnames for consistent output
	var hostnames []string
	for hostname := range s.HostReports {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	for _, hostname := range hostnames {
		report := s.HostReports[hostname]
		content.WriteString(fmt.Sprintf("* link:hosts/%s[%s - %s]\n",
			filepath.Base(report.OutputPath), hostname, report.Title))
	}

	// Write to file
	return os.WriteFile(filename, []byte(content.String()), 0644)
}

// generateKeySection creates the color-coded key section
func (s *SummaryReport) generateKeySection() string {
	return `= Key

[cols="1,3", options=header]
|===
|Value
|Description

|
{set:cellbgcolor:#FF0000}
Changes Required
|
{set:cellbgcolor!}
Indicates Changes Required for system stability, subscription compliance, or other reason.

|
{set:cellbgcolor:#FEFE20}
Changes Recommended
|
{set:cellbgcolor!}
Indicates Changes Recommended to align with recommended practices, but not urgently required

|
{set:cellbgcolor:#A6B9BF}
N/A
|
{set:cellbgcolor!}
No advise given on line item. For line items which are data-only to provide context.

|
{set:cellbgcolor:#80E5FF}
Advisory
|
{set:cellbgcolor!}
No change required or recommended, but additional information provided.

|
{set:cellbgcolor:#00FF00}
No Change
|
{set:cellbgcolor!}
No change required. In alignment with recommended practices.

|
{set:cellbgcolor:#FFFFFF}
To Be Evaluated
|
{set:cellbgcolor!}
Not yet evaluated.
|===

`
}

// generateDashboard creates a visual dashboard
func (s *SummaryReport) generateDashboard() string {
	var sb strings.Builder

	// Simple ASCII visualization
	sb.WriteString("[listing]\n----\n")
	sb.WriteString(fmt.Sprintf("Critical Issues: %s %d\n",
		strings.Repeat("█", min(s.CriticalCount, 20)), s.CriticalCount))
	sb.WriteString(fmt.Sprintf("Warnings:       %s %d\n",
		strings.Repeat("█", min(s.WarningCount, 20)), s.WarningCount))
	sb.WriteString(fmt.Sprintf("Advisory:       %s %d\n",
		strings.Repeat("█", min(s.AdvisoryCount, 20)), s.AdvisoryCount))
	sb.WriteString("----\n\n")

	// Host type breakdown
	sb.WriteString("Host Breakdown:\n\n")
	for hostType, count := range s.HostsByType {
		sb.WriteString(fmt.Sprintf("* %s Systems: %d\n", hostType, count))
	}
	sb.WriteString("\n")

	return sb.String()
}

// groupIssuesBySeverity groups issues by type and severity
func (s *SummaryReport) groupIssuesBySeverity(severity ResultKey) map[string][]IssueSummary {
	grouped := make(map[string][]IssueSummary)

	for hostname, report := range s.HostReports {
		for _, check := range report.Checks {
			if check.Result.ResultKey == severity {
				// Create a key for grouping similar issues
				issueKey := fmt.Sprintf("%s_%s", check.Category, check.Name)

				// Check if this issue type already exists
				found := false
				for i := range grouped[issueKey] {
					if grouped[issueKey][i].Message == check.Result.Message {
						grouped[issueKey][i].Hosts = append(grouped[issueKey][i].Hosts, hostname)
						found = true
						break
					}
				}

				if !found {
					issue := IssueSummary{
						Category:  check.Category,
						CheckName: check.Name,
						Message:   check.Result.Message,
						Severity:  severity,
						Hosts:     []string{hostname},
					}
					if len(check.Result.Recommendations) > 0 {
						issue.Remediation = check.Result.Recommendations[0]
					}
					grouped[issueKey] = append(grouped[issueKey], issue)
				}
			}
		}
	}

	return grouped
}

// formatGroupedIssues formats grouped issues for output
func (s *SummaryReport) formatGroupedIssues(grouped map[string][]IssueSummary) string {
	var sb strings.Builder

	// Sort issue types for consistent output
	var issueTypes []string
	for issueType := range grouped {
		issueTypes = append(issueTypes, issueType)
	}
	sort.Strings(issueTypes)

	for _, issueType := range issueTypes {
		issues := grouped[issueType]
		if len(issues) == 0 {
			continue
		}

		// Use the first issue as representative
		representative := issues[0]

		// Format section header
		icon := "🔴"
		if representative.Severity == ResultKeyRecommended {
			icon = "⚠️"
		}

		sb.WriteString(fmt.Sprintf("=== %s %s (Affects %d hosts)\n\n",
			icon, representative.CheckName, len(representative.Hosts)))

		// Create table for this issue type
		sb.WriteString("[cols=\"2,4,2\", options=header]\n|===\n")
		sb.WriteString("|Host |Issue |Action Required\n\n")

		for _, issue := range issues {
			for _, host := range issue.Hosts {
				sb.WriteString(fmt.Sprintf("|%s |%s |%s\n",
					host, issue.Message, issue.Remediation))
			}
		}
		sb.WriteString("|===\n\n")
	}

	return sb.String()
}

// generatePatternAnalysis creates pattern analysis section
func (s *SummaryReport) generatePatternAnalysis() string {
	var sb strings.Builder

	// Analyze common issues
	commonIssues := s.findCommonPatterns()

	sb.WriteString("=== Common Issues Detected:\n\n")

	for i, pattern := range commonIssues {
		percentage := float64(len(pattern.Hosts)) / float64(s.TotalHosts) * 100
		sb.WriteString(fmt.Sprintf("%d. **%.0f%% of hosts** (%d/%d) %s\n",
			i+1, percentage, len(pattern.Hosts), s.TotalHosts, pattern.Description))
		sb.WriteString(fmt.Sprintf("   - Affected hosts: %s\n",
			strings.Join(pattern.Hosts[:min(5, len(pattern.Hosts))], ", ")))
		if len(pattern.Hosts) > 5 {
			sb.WriteString(fmt.Sprintf("   - ... and %d more\n", len(pattern.Hosts)-5))
		}
		sb.WriteString(fmt.Sprintf("   - Action: %s\n\n", pattern.Recommendation))
	}

	return sb.String()
}

// Pattern represents a common issue pattern
type Pattern struct {
	Description    string
	Hosts          []string
	Recommendation string
}

// findCommonPatterns identifies common issues across hosts
func (s *SummaryReport) findCommonPatterns() []Pattern {
	patternMap := make(map[string]*Pattern)

	// Look for common issues
	for hostname, report := range s.HostReports {
		for _, check := range report.Checks {
			if check.Result.ResultKey == ResultKeyRequired || check.Result.ResultKey == ResultKeyRecommended {
				key := fmt.Sprintf("%s_%s", check.Category, check.Name)

				if pattern, exists := patternMap[key]; exists {
					pattern.Hosts = append(pattern.Hosts, hostname)
				} else {
					rec := "See individual host reports for specific remediation"
					if len(check.Result.Recommendations) > 0 {
						rec = check.Result.Recommendations[0]
					}
					patternMap[key] = &Pattern{
						Description:    check.Result.Message,
						Hosts:          []string{hostname},
						Recommendation: rec,
					}
				}
			}
		}
	}

	// Convert to slice and sort by frequency
	var patterns []Pattern
	for _, pattern := range patternMap {
		if len(pattern.Hosts) >= 2 { // Only show patterns affecting 2+ hosts
			patterns = append(patterns, *pattern)
		}
	}

	sort.Slice(patterns, func(i, j int) bool {
		return len(patterns[i].Hosts) > len(patterns[j].Hosts)
	})

	// Return top patterns
	if len(patterns) > 5 {
		patterns = patterns[:5]
	}

	return patterns
}

// generateHealthMatrix creates the host health matrix
func (s *SummaryReport) generateHealthMatrix() string {
	var sb strings.Builder

	sb.WriteString("[cols=\"3,1,1,1,1,1\", options=header]\n|===\n")
	sb.WriteString("|Host |Type |Critical |Warning |Advisory |Health Score\n\n")

	// Sort hosts for consistent output
	var hostnames []string
	for hostname := range s.HostReports {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	for _, hostname := range hostnames {
		report := s.HostReports[hostname]

		criticalCount := 0
		warningCount := 0
		advisoryCount := 0

		for _, check := range report.Checks {
			switch check.Result.ResultKey {
			case ResultKeyRequired:
				criticalCount++
			case ResultKeyRecommended:
				warningCount++
			case ResultKeyAdvisory:
				advisoryCount++
			}
		}

		hostType := "RHEL"
		if strings.Contains(report.Title, "Satellite") {
			hostType = "Satellite"
		}

		// Determine health score
		healthColor := "#00FF00" // Green - Healthy
		healthStatus := "Healthy"
		if criticalCount > 0 {
			healthColor = "#FF0000" // Red - Critical
			healthStatus = "Critical"
		} else if warningCount > 0 {
			healthColor = "#FEFE20" // Yellow - Warning
			healthStatus = "Warning"
		}

		sb.WriteString(fmt.Sprintf("|link:hosts/%s[%s] |%s |%d |%d |%d |{set:cellbgcolor:%s}%s\n",
			filepath.Base(report.OutputPath), hostname, hostType,
			criticalCount, warningCount, advisoryCount, healthColor, healthStatus))
	}

	sb.WriteString("|===\n\n")
	sb.WriteString("{set:cellbgcolor!}\n\n")

	return sb.String()
}

// GenerateCriticalIssuesReport generates a report focusing only on critical issues
func (s *SummaryReport) GenerateCriticalIssuesReport() error {
	filename := filepath.Join(s.OutputDir, fmt.Sprintf("%s-critical-issues.adoc",
		s.GeneratedTime.Format("2006-01-02-150405")))

	var content strings.Builder

	content.WriteString("= Critical Issues Report\n")
	content.WriteString(fmt.Sprintf("Generated: %s\n", s.GeneratedTime.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Total Critical Issues: %d across %d hosts\n\n",
		s.CriticalCount, s.TotalHosts))

	// Get only critical issues
	criticalIssues := s.groupIssuesBySeverity(ResultKeyRequired)

	if len(criticalIssues) == 0 {
		content.WriteString("== No Critical Issues Found\n\n")
		content.WriteString("All systems are operating within acceptable parameters.\n")
	} else {
		content.WriteString("== Critical Issues Requiring Immediate Attention\n\n")
		content.WriteString(s.formatGroupedIssues(criticalIssues))

		// Add quick remediation guide
		content.WriteString("== Quick Remediation Guide\n\n")
		content.WriteString(s.generateRemediationGuide(criticalIssues))
	}

	return os.WriteFile(filename, []byte(content.String()), 0644)
}

// generateRemediationGuide creates a quick remediation guide
func (s *SummaryReport) generateRemediationGuide(issues map[string][]IssueSummary) string {
	var sb strings.Builder

	sb.WriteString("=== Priority Order:\n\n")
	sb.WriteString("1. Address certificate expiry issues first (if any)\n")
	sb.WriteString("2. Resolve disk space issues\n")
	sb.WriteString("3. Fix security vulnerabilities\n")
	sb.WriteString("4. Address service failures\n\n")

	sb.WriteString("=== Common Remediation Commands:\n\n")
	sb.WriteString("[source,bash]\n----\n")
	sb.WriteString("# For certificate issues on Satellite:\n")
	sb.WriteString("satellite-installer --scenario satellite --certs-regenerate\n\n")
	sb.WriteString("# For disk space issues:\n")
	sb.WriteString("foreman-maintain content clean-pulp-cache\n")
	sb.WriteString("find /var/log -name '*.log' -mtime +30 -delete\n\n")
	sb.WriteString("# For subscription issues:\n")
	sb.WriteString("subscription-manager refresh\n")
	sb.WriteString("subscription-manager attach --auto\n")
	sb.WriteString("----\n\n")

	return sb.String()
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
