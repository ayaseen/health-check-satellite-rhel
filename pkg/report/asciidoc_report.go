// pkg/report/asciidoc.go

package report

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Status represents the result status of a check
type Status string

const (
	// StatusOK indicates everything is working correctly
	StatusOK Status = "OK"

	// StatusWarning indicates a potential issue that should be addressed
	StatusWarning Status = "Warning"

	// StatusCritical Status = "Critical" indicates a critical issue that requires immediate attention
	StatusCritical Status = "Critical"

	// StatusInfo indicates informational output
	StatusInfo Status = "Info"

	// StatusNotApplicable indicates the check does not apply to this environment
	StatusNotApplicable Status = "Not Applicable"
)

// ResultKey represents the level of importance for a result in a report summary
type ResultKey string

const (
	// ResultKeyNoChange indicates no changes are needed
	ResultKeyNoChange ResultKey = "nochange"

	// ResultKeyRecommended indicates changes are recommended
	ResultKeyRecommended ResultKey = "recommended"

	// ResultKeyRequired indicates changes are required
	ResultKeyRequired ResultKey = "required"

	// ResultKeyAdvisory indicates additional information
	ResultKeyAdvisory ResultKey = "advisory"

	// ResultKeyNotApplicable indicates the check does not apply
	ResultKeyNotApplicable ResultKey = "na"

	// ResultKeyEvaluate indicates the result needs evaluation
	ResultKeyEvaluate ResultKey = "eval"
)

// Category represents a category of checks
type Category string

const (
	// CategorySystemInfo is for system information checks
	CategorySystemInfo Category = "System Information"

	// CategoryPerformance is for performance-related checks
	CategoryPerformance Category = "Performance"

	// CategoryStorage is for storage-related checks
	CategoryStorage Category = "Storage"

	// CategorySecurity is for security-related checks
	CategorySecurity Category = "Security"

	// CategoryServices is for service-related checks
	CategoryServices Category = "Services"

	// CategoryNetworking is for networking-related checks
	CategoryNetworking Category = "Networking"

	// CategoryUpdates is for update-related checks
	CategoryUpdates Category = "Updates"

	// CategorySatelliteSystem is for Satellite system checks
	CategorySatelliteSystem Category = "Satellite System"

	// CategorySatelliteStorage is for Satellite storage checks
	CategorySatelliteStorage Category = "Satellite Storage"

	// CategorySatelliteContent is for Satellite content checks
	CategorySatelliteContent Category = "Satellite Content"
)

// Result represents the result of a check
type Result struct {
	// Status indicates the result status (OK, Warning, Critical, etc.)
	Status Status

	// Message is a brief description of the result
	Message string

	// ResultKey indicates the importance of the result
	ResultKey ResultKey

	// Detail provides detailed information about the result
	Detail string

	// Recommendations are suggestions to address any issues
	Recommendations []string

	// ReferenceLinks contains documentation references
	ReferenceLinks []string
}

// Check represents a health check
type Check struct {
	// ID is the unique identifier for the check
	ID string

	// Name is the human-readable name for the check
	Name string

	// Description describes what the check does
	Description string

	// Category identifies the category this check belongs to
	Category Category

	// Result contains the check result
	Result Result
}

// AsciiDocReport generates AsciiDoc reports for health checks
type AsciiDocReport struct {
	// OutputPath is where the report will be saved
	OutputPath string

	// Hostname is the hostname of the system being checked
	Hostname string

	// Title is the title of the report
	Title string

	// Checks are all the checks performed for this report
	Checks []*Check
}

// NewAsciiDocReport creates a new AsciiDoc report
func NewAsciiDocReport(outputPath string) *AsciiDocReport {
	return &AsciiDocReport{
		OutputPath: outputPath,
		Checks:     []*Check{},
	}
}

// Initialize sets up the report with hostname and title
func (r *AsciiDocReport) Initialize(hostname, title string) {
	r.Hostname = hostname
	r.Title = title
}

// AddCheck adds a check to the report
func (r *AsciiDocReport) AddCheck(check *Check) {
	r.Checks = append(r.Checks, check)
}

// Generate generates the report and writes it to the output path
func (r *AsciiDocReport) Generate() (string, error) {
	// Create the output directory if it doesn't exist
	outputDir := filepath.Dir(r.OutputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate the report content
	content := r.generateReportContent()

	// Write to file
	if err := os.WriteFile(r.OutputPath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return r.OutputPath, nil
}

// generateReportContent creates the full report content
func (r *AsciiDocReport) generateReportContent() string {
	var sb strings.Builder

	// Add report header
	sb.WriteString(fmt.Sprintf("= %s\n\n", r.Title))
	sb.WriteString("ifdef::env-github[]\n:tip-caption: :bulb:\n:note-caption: :information_source:\n:important-caption: :heavy_exclamation_mark:\n:caution-caption: :fire:\n:warning-caption: :warning:\nendif::[]\n\n")

	// Add key section
	sb.WriteString(r.generateKeySection())

	// Add summary section
	sb.WriteString(r.generateSummarySection())

	// Add detailed category sections with tables followed by check details
	categorizedChecks := r.organizeChecksByCategory()
	orderedCategories := r.getSortedCategories()

	// Add each category section
	for _, category := range orderedCategories {
		checks, exists := categorizedChecks[category]
		if !exists || len(checks) == 0 {
			continue
		}

		sb.WriteString(r.generateCategorySection(category, checks))
	}

	// Reset bgcolor for future tables
	sb.WriteString("// Reset bgcolor for future tables\n[grid=none,frame=none]\n|===\n|{set:cellbgcolor!}\n|===\n\n")

	return sb.String()
}

// generateKeySection creates the color-coded key section
func (r *AsciiDocReport) generateKeySection() string {
	var sb strings.Builder

	sb.WriteString("= Key\n\n")
	sb.WriteString("[cols=\"1,3\", options=header]\n|===\n|Value\n|Description\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#FF0000}\nChanges Required\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("Indicates Changes Required for system stability, subscription compliance, or other reason.\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#FEFE20}\nChanges Recommended\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("Indicates Changes Recommended to align with recommended practices, but not urgently required\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#A6B9BF}\nN/A\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("No advise given on line item. For line items which are data-only to provide context.\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#80E5FF}\nAdvisory\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("No change required or recommended, but additional information provided.\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#00FF00}\nNo Change\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("No change required. In alignment with recommended practices.\n\n")

	sb.WriteString("|\n{set:cellbgcolor:#FFFFFF}\nTo Be Evaluated\n|\n{set:cellbgcolor!}\n")
	sb.WriteString("Not yet evaluated. Will appear only in draft copies.\n|===\n\n")

	return sb.String()
}

// generateSummarySection generates the summary section with all checks
func (r *AsciiDocReport) generateSummarySection() string {
	var sb strings.Builder

	sb.WriteString("= Summary\n\n")
	sb.WriteString("[cols=\"1,2,2,3\", options=header]\n|===\n|*Category*\n|*Item Evaluated*\n|*Observed Result*\n|*Recommendation*\n\n")

	// Organize checks by category
	categorizedChecks := r.organizeChecksByCategory()

	// Get ordered categories
	orderedCategories := r.getSortedCategories()

	// Process checks in order by category
	for _, category := range orderedCategories {
		checks, exists := categorizedChecks[category]
		if !exists || len(checks) == 0 {
			continue
		}

		// Process all checks in this category
		for _, check := range checks {
			// Category column
			sb.WriteString("// ------------------------ITEM START\n")
			sb.WriteString("// ----ITEM SOURCE:  ./content/healthcheck-items/" + check.ID + ".item\n\n")
			sb.WriteString("// Category\n")
			sb.WriteString("|\n{set:cellbgcolor!}\n" + string(check.Category) + "\n\n")

			// Item Evaluated column with link to detailed section
			sb.WriteString("// Item Evaluated\n")
			sb.WriteString("a|\n<<" + check.Name + ">>\n\n")

			// Observed Result column
			sb.WriteString("| " + check.Result.Message + " \n\n")

			// Recommendation column with proper coloring
			sb.WriteString(getResultFormatting(check.Result.ResultKey) + "\n\n")
			sb.WriteString("// ------------------------ITEM END\n\n")
		}
	}

	sb.WriteString("|===\n\n")
	sb.WriteString("<<<\n\n")
	sb.WriteString("{set:cellbgcolor!}\n\n")

	return sb.String()
}

// generateCategorySection creates a section for a specific category
func (r *AsciiDocReport) generateCategorySection(category Category, checks []*Check) string {
	var sb strings.Builder

	// Add category heading
	sb.WriteString(fmt.Sprintf("# %s\n\n", category))

	// Start category table
	sb.WriteString("[cols=\"1,2,2,3\", options=header]\n|===\n|*Category*\n|*Item Evaluated*\n|*Observed Result*\n|*Recommendation*\n\n")

	// Add all checks for this category
	for _, check := range checks {
		// Category column
		sb.WriteString("// ------------------------ITEM START\n")
		sb.WriteString("// ----ITEM SOURCE:  ./content/healthcheck-items/" + check.ID + ".item\n\n")
		sb.WriteString("// Category\n")
		sb.WriteString("|\n{set:cellbgcolor!}\n" + string(check.Category) + "\n\n")

		// Item Evaluated column with link to detailed section
		sb.WriteString("// Item Evaluated\n")
		sb.WriteString("a|\n<<" + check.Name + ">>\n\n")

		// Observed Result column
		sb.WriteString("| " + check.Result.Message + " \n\n")

		// Recommendation column with proper coloring
		sb.WriteString(getResultFormatting(check.Result.ResultKey) + "\n\n")
		sb.WriteString("// ------------------------ITEM END\n")
	}

	sb.WriteString("|===\n\n")

	// Add detailed sections for each check in this category
	for _, check := range checks {
		sb.WriteString(r.formatCheckDetail(check))
	}

	sb.WriteString("<<<\n\n")
	sb.WriteString("{set:cellbgcolor!}\n\n")

	return sb.String()
}

// formatCheckDetail formats detailed information about a check
func (r *AsciiDocReport) formatCheckDetail(check *Check) string {
	var sb strings.Builder

	// Add section with check name
	sb.WriteString(fmt.Sprintf("== %s\n\n", check.Name))

	// Add result status
	sb.WriteString(getStatusTable(check.Result.ResultKey) + "\n\n")

	// Add detail if available
	if check.Result.Detail != "" {
		// Check if the detail already contains source blocks or formatted content
		if isAlreadyFormatted(check.Result.Detail) {
			sb.WriteString(check.Result.Detail)

			// Ensure there's proper spacing after the detail
			if !strings.HasSuffix(check.Result.Detail, "\n\n") {
				if strings.HasSuffix(check.Result.Detail, "\n") {
					sb.WriteString("\n")
				} else {
					sb.WriteString("\n\n")
				}
			}
		} else {
			// Format as code block
			sb.WriteString(formatAsCodeBlock(check.Result.Detail, ""))
		}
	}

	// Add observation
	sb.WriteString("**Observation**\n\n")
	sb.WriteString(check.Result.Message + "\n\n")

	// Add recommendations
	sb.WriteString("**Recommendation**\n\n")
	if len(check.Result.Recommendations) > 0 {
		for _, rec := range check.Result.Recommendations {
			sb.WriteString(rec + "\n\n")
		}
	} else {
		sb.WriteString("None\n\n")
	}

	// Add reference links
	sb.WriteString("*Reference Link(s)*\n\n")
	if len(check.Result.ReferenceLinks) > 0 {
		for _, link := range check.Result.ReferenceLinks {
			sb.WriteString("* " + link + "\n\n")
		}
	} else {
		// No specific reference found, use default
		if strings.Contains(string(check.Category), "Satellite") {
			sb.WriteString("* https://docs.redhat.com/en/documentation/red_hat_satellite/\n\n")
		} else {
			sb.WriteString("* https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/\n\n")
		}
	}

	return sb.String()
}

// organizeChecksByCategory groups checks by their category
func (r *AsciiDocReport) organizeChecksByCategory() map[Category][]*Check {
	categorized := make(map[Category][]*Check)

	for _, check := range r.Checks {
		categorized[check.Category] = append(categorized[check.Category], check)
	}

	return categorized
}

// getSortedCategories returns categories in the preferred order
func (r *AsciiDocReport) getSortedCategories() []Category {
	return []Category{
		CategorySystemInfo,
		CategoryPerformance,
		CategoryStorage,
		CategorySecurity,
		CategoryServices,
		CategoryNetworking,
		CategoryUpdates,
		CategorySatelliteSystem,
		CategorySatelliteStorage,
		CategorySatelliteContent,
	}
}

// getResultFormatting returns formatted AsciiDoc for a result key (used in tables)
func getResultFormatting(resultKey ResultKey) string {
	options := map[ResultKey]string{
		ResultKeyRequired: `| 
{set:cellbgcolor:#FF0000}
Changes Required`,
		ResultKeyRecommended: `| 
{set:cellbgcolor:#FEFE20}
Changes Recommended`,
		ResultKeyNoChange: `| 
{set:cellbgcolor:#00FF00}
No Change`,
		ResultKeyAdvisory: `| 
{set:cellbgcolor:#80E5FF}
Advisory`,
		ResultKeyNotApplicable: `| 
{set:cellbgcolor:#A6B9BF}
Not Applicable`,
		ResultKeyEvaluate: `| 
{set:cellbgcolor:#FFFFFF}
To Be Evaluated`,
	}

	result, ok := options[resultKey]
	if !ok {
		return options[ResultKeyEvaluate]
	}
	return result
}

// getStatusTable returns a colored status table for a result key (used in detailed sections)
func getStatusTable(resultKey ResultKey) string {
	options := map[ResultKey]string{
		ResultKeyRequired: `[cols="^"] 
|===
|
{set:cellbgcolor:#FF0000}
Changes Required
|===`,
		ResultKeyRecommended: `[cols="^"] 
|===
|
{set:cellbgcolor:#FEFE20}
Changes Recommended
|===`,
		ResultKeyNoChange: `[cols="^"] 
|===
|
{set:cellbgcolor:#00FF00}
No Change
|===`,
		ResultKeyAdvisory: `[cols="^"] 
|===
|
{set:cellbgcolor:#80E5FF}
Advisory
|===`,
		ResultKeyNotApplicable: `[cols="^"] 
|===
|
{set:cellbgcolor:#A6B9BF}
Not Applicable
|===`,
		ResultKeyEvaluate: `[cols="^"] 
|===
|
{set:cellbgcolor:#FFFFFF}
To Be Evaluated
|===`,
	}

	result, ok := options[resultKey]
	if !ok {
		return options[ResultKeyEvaluate]
	}
	return result
}

// isAlreadyFormatted checks if text already contains source blocks or other formatting
func isAlreadyFormatted(text string) bool {
	// Check for AsciiDoc source blocks with different variations
	if strings.Contains(text, "[source,") ||
		strings.Contains(text, "[source, ") ||
		strings.Contains(text, "[source=") ||
		strings.Contains(text, "----") ||
		strings.Contains(text, "....") {
		return true
	}

	// Check for AsciiDoc tables
	if strings.Contains(text, "|===") ||
		strings.Contains(text, "[cols=") {
		return true
	}

	// Check for other AsciiDoc formatting elements
	if strings.Contains(text, "== ") ||
		strings.Contains(text, "=== ") {
		return true
	}

	// Check for complex YAML or JSON structure
	if (strings.Contains(text, "apiVersion:") && strings.Contains(text, "kind:")) ||
		(strings.Contains(text, "metadata:") && strings.Contains(text, "spec:")) {
		return true
	}

	return false
}

// formatAsCodeBlock formats text as a source code block with the appropriate language
func formatAsCodeBlock(content string, language string) string {
	// Skip if already formatted
	if isAlreadyFormatted(content) {
		return content
	}

	// Default to yaml for structured data with common patterns
	if language == "" {
		if strings.Contains(content, "rpm -qa") ||
			strings.Contains(content, "yum") ||
			strings.Contains(content, "dnf") ||
			strings.Contains(content, "kernel") ||
			strings.Contains(content, "package") {
			language = "bash"
		} else if (strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:")) ||
			(strings.Contains(content, "metadata:") && strings.Contains(content, "spec:")) {
			language = "yaml"
		} else if strings.HasPrefix(strings.TrimSpace(content), "{") && strings.Contains(content, "\":") {
			language = "json"
		} else if strings.Contains(content, "NAME") && strings.Contains(content, "READY") {
			language = "bash"
		} else {
			language = "text"
		}
	}

	// Clean up content to ensure proper formatting
	// Trim trailing whitespace but leave content newlines intact
	content = strings.TrimRight(content, " \t")

	// Make sure there's exactly one newline at the end of content
	content = strings.TrimRight(content, "\n") + "\n"

	// Ensure proper spacing in the AsciiDoc format
	return fmt.Sprintf("[source, %s]\n----\n%s----\n\n", language, content)
}

// NewCheck creates a new Check
func NewCheck(id, name, description string, category Category) *Check {
	return &Check{
		ID:          id,
		Name:        name,
		Description: description,
		Category:    category,
	}
}

// NewResult creates a new Result
func NewResult(status Status, message string, resultKey ResultKey) Result {
	return Result{
		Status:          status,
		Message:         message,
		ResultKey:       resultKey,
		Recommendations: []string{},
		ReferenceLinks:  []string{},
	}
}

// AddReferenceLink adds a reference link to a Result
func AddReferenceLink(result *Result, link string) {
	result.ReferenceLinks = append(result.ReferenceLinks, link)
}

// AddRecommendation adds a recommendation to a Result
func AddRecommendation(result *Result, recommendation string) {
	result.Recommendations = append(result.Recommendations, recommendation)
}

// SetDetail sets the detail for a Result
func SetDetail(result *Result, detail string) {
	// Normalize line endings
	detail = strings.ReplaceAll(detail, "\r\n", "\n")

	// Ensure trailing newline for command output
	if !strings.HasSuffix(detail, "\n") {
		detail += "\n"
	}

	result.Detail = detail
}

// LoadFromFile loads check results from a generated report file
func (r *AsciiDocReport) LoadFromFile(filepath string) error {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read report file: %v", err)
	}

	contentStr := string(content)

	// Initialize checks slice
	r.Checks = []*Check{}

	// Split content into lines for parsing
	lines := strings.Split(contentStr, "\n")

	// Variables to track parsing state
	inTable := false
	var currentCategory Category
	tableStartLine := -1

	// Parse line by line
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Detect table start - look for the header row pattern
		if strings.Contains(line, "|===") && i+1 < len(lines) {
			nextLine := lines[i+1]
			if strings.Contains(nextLine, "Category") &&
				strings.Contains(nextLine, "Item Evaluated") &&
				strings.Contains(nextLine, "Observed Result") &&
				strings.Contains(nextLine, "Recommendation") {
				inTable = true
				tableStartLine = i
				i++ // Skip the header line
				continue
			}
		}

		// Detect table end
		if inTable && strings.TrimSpace(line) == "|===" && i > tableStartLine+2 {
			inTable = false
			continue
		}

		// Parse table rows
		if inTable && strings.HasPrefix(strings.TrimSpace(line), "|") {
			// Split by | and clean up
			parts := strings.Split(line, "|")

			// Filter out empty parts
			var cleanParts []string
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" {
					cleanParts = append(cleanParts, trimmed)
				}
			}

			// We need at least 4 parts: Category, Item Evaluated, Observed Result, Recommendation
			if len(cleanParts) >= 4 {
				category := cleanParts[0]
				itemEvaluated := cleanParts[1]
				observedResult := cleanParts[2]
				recommendation := cleanParts[3]

				// Skip header row or empty rows
				if category == "Category" || category == "" {
					continue
				}

				// Update category if it's specified
				if category != "" && !strings.Contains(category, "{set:") {
					currentCategory = Category(category)
				}

				// Clean up item evaluated - remove link markup if present
				checkName := itemEvaluated
				if strings.Contains(itemEvaluated, "<<") && strings.Contains(itemEvaluated, ">>") {
					// Extract text between << and >>
					start := strings.Index(itemEvaluated, "<<") + 2
					end := strings.Index(itemEvaluated, ">>")
					if start < end && end > 0 {
						checkName = itemEvaluated[start:end]
					}
				} else if strings.HasPrefix(itemEvaluated, "link:") {
					// Handle link: format
					linkStart := strings.Index(itemEvaluated, "[") + 1
					linkEnd := strings.Index(itemEvaluated, "]")
					if linkStart < linkEnd && linkEnd > 0 {
						checkName = itemEvaluated[linkStart:linkEnd]
					}
				}

				// Create the check
				check := &Check{
					ID:          fmt.Sprintf("%s-%s", currentCategory, strings.ReplaceAll(checkName, " ", "-")),
					Name:        checkName,
					Description: observedResult,
					Category:    currentCategory,
				}

				// Determine status based on recommendation column
				// The recommendation contains both color formatting and text
				var resultKey ResultKey
				var status Status

				// Remove color formatting to get clean text
				cleanRec := recommendation
				// Remove {set:cellbgcolor:#...} patterns
				colorPattern := regexp.MustCompile(`\{set:cellbgcolor:[^}]*\}`)
				cleanRec = colorPattern.ReplaceAllString(cleanRec, "")
				cleanRec = strings.TrimSpace(cleanRec)

				// Check for the actual status text
				if strings.Contains(cleanRec, "Changes Required") ||
					strings.Contains(recommendation, "#FF0000") { // Red color
					resultKey = ResultKeyRequired
					status = StatusCritical
				} else if strings.Contains(cleanRec, "Changes Recommended") ||
					strings.Contains(recommendation, "#FEFE20") { // Yellow color
					resultKey = ResultKeyRecommended
					status = StatusWarning
				} else if strings.Contains(cleanRec, "Advisory") ||
					strings.Contains(recommendation, "#80E5FF") { // Light blue color
					resultKey = ResultKeyAdvisory
					status = StatusInfo
				} else if strings.Contains(cleanRec, "No Change") ||
					strings.Contains(recommendation, "#00FF00") { // Green color
					resultKey = ResultKeyNoChange
					status = StatusOK
				} else if strings.Contains(cleanRec, "N/A") ||
					strings.Contains(recommendation, "#A6B9BF") { // Gray color
					resultKey = ResultKeyNoChange
					status = StatusInfo
				} else {
					// Default case
					resultKey = ResultKeyNoChange
					status = StatusInfo
				}

				// Create the result
				check.Result = NewResult(status, observedResult, resultKey)

				// Add the check
				r.Checks = append(r.Checks, check)
			}
		}
	}

	// Also extract hostname and title if not set
	if r.Hostname == "" {
		// Look for hostname in the content
		for _, line := range lines {
			if strings.Contains(line, "Hostname:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					r.Hostname = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	if r.Title == "" {
		// Look for title (first line starting with =)
		for _, line := range lines {
			if strings.HasPrefix(line, "= ") && !strings.HasPrefix(line, "==") {
				r.Title = strings.TrimSpace(strings.TrimPrefix(line, "= "))
				break
			}
		}
	}

	return nil
}
