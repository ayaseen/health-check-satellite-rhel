// pkg/checks/satellite/common.go

package satellite

import (
	"fmt"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"regexp"
	"strings"
)

// VersionInfo stores Satellite version components
type VersionInfo struct {
	FullVersion  string
	MajorVersion string
	MinorVersion string
}

// NOTE: GetSatelliteVersion is already defined in system.go,
// so we don't redefine it here to avoid duplication

// getDefaultOrganizationID attempts to find the default organization ID
func getDefaultOrganizationID() string {
	// Try to get the organization list
	orgListCmd := "hammer organization list --fields id,name"
	orgListOutput, err := utils.RunCommand("bash", "-c", orgListCmd)
	if err != nil {
		return ""
	}

	// Parse the output to find the ID of the first organization
	orgLines := strings.Split(orgListOutput, "\n")
	for _, line := range orgLines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Split(line, "|")
			if len(fields) >= 2 {
				orgID := strings.TrimSpace(fields[1])
				if orgID != "" {
					// Verify that the org ID is numeric
					if _, err := regexp.MatchString(`^\d+$`, orgID); err == nil {
						return orgID
					}
				}
			}
		}
	}

	// If we couldn't find any organization, return empty string
	return ""
}

// safeOrganizationFlag returns the organization flag if the org ID is valid, or empty string otherwise
func safeOrganizationFlag(organization string) string {
	if organization == "" {
		return ""
	}

	// Check if organization is numeric
	if matched, _ := regexp.MatchString(`^\d+$`, organization); matched {
		return fmt.Sprintf(" --organization-id %s", organization)
	}

	// If not numeric, try to use organization name with --organization flag
	return fmt.Sprintf(" --organization \"%s\"", organization)
}
