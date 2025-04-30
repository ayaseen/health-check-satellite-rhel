// pkg/checks/satellite/user.go

package satellite

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunUserChecks performs Satellite user and permission checks
func RunUserChecks(r *report.AsciiDocReport) {
	// Check user accounts and permissions
	checkUserAccounts(r)

	// Check role configuration
	checkRoleConfiguration(r)

	// Check user activity and access
	checkUserActivity(r)
}

// checkUserAccounts checks user accounts and permissions
func checkUserAccounts(r *report.AsciiDocReport) {
	checkID := "satellite-user-accounts"
	checkName := "User Accounts"
	checkDesc := "Checks user accounts and their permissions."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all users
	usersCmd := "hammer user list"
	usersOutput, err := utils.RunCommand("bash", "-c", usersCmd)

	var detail strings.Builder
	detail.WriteString("User Accounts Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving user accounts:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve user account information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_users_and_roles_admin",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("User Accounts:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(usersOutput)
	detail.WriteString("\n----\n\n")

	// Check admin user
	adminUserCmd := "hammer user info --id 4 || hammer user info --login admin"
	adminUserOutput, _ := utils.RunCommand("bash", "-c", adminUserCmd)

	detail.WriteString("Admin User Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(adminUserOutput)
	detail.WriteString("\n----\n\n")

	// Check authentication sources
	authSourcesCmd := "hammer auth-source list"
	authSourcesOutput, _ := utils.RunCommand("bash", "-c", authSourcesCmd)

	detail.WriteString("Authentication Sources:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(authSourcesOutput)
	detail.WriteString("\n----\n\n")

	// Check user groups
	userGroupsCmd := "hammer user-group list"
	userGroupsOutput, _ := utils.RunCommand("bash", "-c", userGroupsCmd)

	detail.WriteString("User Groups:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(userGroupsOutput)
	detail.WriteString("\n----\n\n")

	// Check external user groups if LDAP is configured
	if strings.Contains(authSourcesOutput, "LDAP") {
		extGroupsCmd := "hammer user-group list --search 'auth_source = LDAP'"
		extGroupsOutput, _ := utils.RunCommand("bash", "-c", extGroupsCmd)

		detail.WriteString("External User Groups:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(extGroupsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Count users by type
	totalUsers := 0
	adminUsers := 0
	regularUsers := 0
	internalAuth := 0
	externalAuth := 0

	lines := strings.Split(usersOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalUsers++

			// Count admin users (with admin rights)
			if strings.Contains(line, "admin") || strings.Contains(line, "Administrator") {
				adminUsers++
			} else {
				regularUsers++
			}

			// Count auth source
			if strings.Contains(line, "Internal") || strings.Contains(line, "INTERNAL") {
				internalAuth++
			} else if strings.Contains(line, "LDAP") || strings.Contains(line, "EXTERNAL") {
				externalAuth++
			}
		}
	}

	detail.WriteString("User Account Summary:\n")
	detail.WriteString(fmt.Sprintf("- Total Users: %d\n", totalUsers))
	detail.WriteString(fmt.Sprintf("- Admin Users: %d\n", adminUsers))
	detail.WriteString(fmt.Sprintf("- Regular Users: %d\n", regularUsers))
	detail.WriteString(fmt.Sprintf("- Internal Authentication: %d\n", internalAuth))
	detail.WriteString(fmt.Sprintf("- External Authentication: %d\n", externalAuth))

	// Evaluate results

	hasDefaultAdmin := strings.Contains(adminUserOutput, "Login: admin")
	hasMultipleAdmins := adminUsers > 1
	hasSingleUser := totalUsers <= 1

	if hasSingleUser {
		check.Result = report.NewResult(report.StatusWarning,
			"Only the default admin user found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create additional user accounts for individual accountability")
		report.AddRecommendation(&check.Result, "Configure user groups and roles for proper access control")
	} else if hasDefaultAdmin && hasMultipleAdmins {
		check.Result = report.NewResult(report.StatusWarning,
			"Default admin account active with multiple admin users",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider disabling or renaming the default admin account")
		report.AddRecommendation(&check.Result, "Use named admin accounts for accountability")
	} else if hasDefaultAdmin {
		check.Result = report.NewResult(report.StatusWarning,
			"Default admin account is still active",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider creating named admin accounts for accountability")
		report.AddRecommendation(&check.Result, "Update the default admin password regularly")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d user accounts configured with proper admin separation", totalUsers),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_users_and_roles_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRoleConfiguration checks role configuration and permissions
func checkRoleConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-roles"
	checkName := "Role Configuration"
	checkDesc := "Checks role configuration and permissions."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all roles
	rolesCmd := "hammer role list"
	rolesOutput, err := utils.RunCommand("bash", "-c", rolesCmd)

	var detail strings.Builder
	detail.WriteString("Role Configuration Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving roles:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve role information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_users_and_roles_admin",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Roles:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rolesOutput)
	detail.WriteString("\n----\n\n")

	// Get built-in roles
	builtinRolesCmd := "hammer role list --search 'builtin = true'"
	builtinRolesOutput, _ := utils.RunCommand("bash", "-c", builtinRolesCmd)

	detail.WriteString("Built-in Roles:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(builtinRolesOutput)
	detail.WriteString("\n----\n\n")

	// Get custom roles
	customRolesCmd := "hammer role list --search 'builtin = false'"
	customRolesOutput, _ := utils.RunCommand("bash", "-c", customRolesCmd)

	detail.WriteString("Custom Roles:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(customRolesOutput)
	detail.WriteString("\n----\n\n")

	// Get filters for key roles
	// Get role IDs first
	roleIdsCmd := "hammer role list --search 'name ~ \"Admin|Manager|Viewer\"' | grep -v '^--\\|^ID' | awk '{print $1}'"
	roleIdsOutput, _ := utils.RunCommand("bash", "-c", roleIdsCmd)
	roleIds := strings.Split(strings.TrimSpace(roleIdsOutput), "\n")

	detail.WriteString("Filters for Key Roles:\n")

	for _, id := range roleIds {
		if id == "" {
			continue
		}

		roleInfoCmd := fmt.Sprintf("hammer role filters --id %s", id)
		roleInfoOutput, _ := utils.RunCommand("bash", "-c", roleInfoCmd)

		detail.WriteString(fmt.Sprintf("Role ID %s Filters:\n", id))
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(roleInfoOutput)
		detail.WriteString("\n----\n")
		detail.WriteString(strings.Repeat("-", 40) + "\n\n")
	}

	// Check user-role assignments
	userRolesCmd := "hammer user list --fields id,login,admin,mail,roles"
	userRolesOutput, _ := utils.RunCommand("bash", "-c", userRolesCmd)

	detail.WriteString("User Role Assignments:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(userRolesOutput)
	detail.WriteString("\n----\n")

	// Count roles by type
	totalRoles := 0
	builtinRoles := 0
	customRoles := 0
	adminRoles := 0

	lines := strings.Split(rolesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalRoles++
		}
	}

	lines = strings.Split(builtinRolesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			builtinRoles++
		}
	}

	lines = strings.Split(customRolesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			customRoles++

			// Count admin-like roles
			if strings.Contains(strings.ToLower(line), "admin") {
				adminRoles++
			}
		}
	}

	// Evaluate results
	hasCustomRoles := customRoles > 0
	hasTooManyAdminRoles := adminRoles > 3 // Arbitrary threshold

	if !hasCustomRoles {
		check.Result = report.NewResult(report.StatusWarning,
			"No custom roles detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create custom roles for more granular access control")
		report.AddRecommendation(&check.Result, "Consider roles based on job responsibilities")
	} else if hasTooManyAdminRoles {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of admin-like roles (%d)", adminRoles),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review admin roles and consolidate if possible")
		report.AddRecommendation(&check.Result, "Ensure principle of least privilege")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d total roles (%d custom) configured appropriately", totalRoles, customRoles),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_users_and_roles_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkUserActivity checks user activity and access logs
func checkUserActivity(r *report.AsciiDocReport) {
	checkID := "satellite-user-activity"
	checkName := "User Activity"
	checkDesc := "Checks user activity and access logs."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("User Activity Analysis:\n\n")

	// Check for recent user logins
	loginAuditCmd := "hammer audit list --search 'action ~ login' --per-page 20"
	loginAuditOutput, err := utils.RunCommand("bash", "-c", loginAuditCmd)

	if err != nil {
		detail.WriteString("Error retrieving login audit logs:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")
	} else {
		detail.WriteString("Recent User Logins:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(loginAuditOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for failed login attempts
	failedLoginCmd := "hammer audit list --search 'action ~ login and auditable_type = User and action ~ failed' --per-page 15"
	failedLoginOutput, _ := utils.RunCommand("bash", "-c", failedLoginCmd)

	detail.WriteString("Failed Login Attempts:\n")
	if strings.Contains(failedLoginOutput, "No audits found") {
		detail.WriteString("No failed login attempts found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(failedLoginOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for user creation/modification
	userModCmd := "hammer audit list --search 'action ~ create or action ~ update and auditable_type = User' --per-page 15"
	userModOutput, _ := utils.RunCommand("bash", "-c", userModCmd)

	detail.WriteString("Recent User Creation/Modification:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(userModOutput)
	detail.WriteString("\n----\n\n")

	// Check for user permissions changes
	permChangeCmd := "hammer audit list --search 'action ~ update and (auditable_type = Role or auditable_type = Filter)' --per-page 15"
	permChangeOutput, _ := utils.RunCommand("bash", "-c", permChangeCmd)

	detail.WriteString("Recent Permission Changes:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(permChangeOutput)
	detail.WriteString("\n----\n\n")

	// Check for inactive users
	inactiveCmd := "hammer user list --search 'last_login < \"30 days ago\"' || echo 'Cannot query by last login'"
	inactiveOutput, _ := utils.RunCommand("bash", "-c", inactiveCmd)

	detail.WriteString("Potentially Inactive Users:\n")
	if !strings.Contains(inactiveOutput, "Cannot query") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(inactiveOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("Could not determine inactive users\n\n")

		// Alternative check for all users
		allUsersCmd := "hammer user list"
		allUsersOutput, _ := utils.RunCommand("bash", "-c", allUsersCmd)
		detail.WriteString("All Users (please check last login dates manually):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(allUsersOutput)
		detail.WriteString("\n----\n")
	}

	// Count login failures and active/inactive users
	failedLogins := 0
	inactiveUsers := 0

	if !strings.Contains(failedLoginOutput, "No audits found") {
		lines := strings.Split(failedLoginOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "failed") {
				failedLogins++
			}
		}
	}

	if !strings.Contains(inactiveOutput, "Cannot query") && !strings.Contains(inactiveOutput, "No users found") {
		lines := strings.Split(inactiveOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
				inactiveUsers++
			}
		}
	}

	// Evaluate results
	highFailedLogins := failedLogins > 10 // Arbitrary threshold
	hasInactiveUsers := inactiveUsers > 0

	if highFailedLogins {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of failed login attempts (%d)", failedLogins),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate failed login attempts for security concerns")
		report.AddRecommendation(&check.Result, "Consider implementing account lockout policies")
	} else if hasInactiveUsers {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d potentially inactive users detected", inactiveUsers),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review and disable or remove inactive user accounts")
		report.AddRecommendation(&check.Result, "Implement a regular user account review process")
	} else if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not fully analyze user activity",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Manually review user activity in the Satellite web UI")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"User activity appears normal with no security concerns",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/managing_users_and_roles_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
